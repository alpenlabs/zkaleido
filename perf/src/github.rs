use reqwest::Client;
use serde_json::json;

use crate::args::EvalArgs;

/// Posts the message to the PR on the github.
///
/// Updates an existing previous comment (if there is one) or posts a new comment.
pub async fn post_to_github_pr(
    args: &EvalArgs,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    // Get all comments on the PR
    const BASE_URL: &str = "https://api.github.com/repos/alpenlabs/zkvm";
    let comments_url = format!("{}/issues/{}/comments", BASE_URL, &args.pr_number);
    let comments_response = client
        .get(&comments_url)
        .header("Authorization", format!("Bearer {}", &args.github_token))
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "strata-perf-bot")
        .send()
        .await?;

    let comments: Vec<serde_json::Value> = comments_response.json().await?;

    // Look for an existing comment from our bot
    let bot_comment = comments.iter().find(|comment| {
        comment["user"]["login"]
            .as_str()
            .map(|login| login == "github-actions[bot]")
            .unwrap_or(false)
    });

    if let Some(existing_comment) = bot_comment {
        // Update the existing comment
        let comment_url = existing_comment["url"].as_str().unwrap();
        let response = client
            .patch(comment_url)
            .header("Authorization", format!("Bearer {}", &args.github_token))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "strata-perf-bot")
            .json(&json!({
                "body": message
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to update comment: {:?}", response.text().await?).into());
        }
    } else {
        // Create a new comment
        let response = client
            .post(&comments_url)
            .header("Authorization", format!("Bearer {}", &args.github_token))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "strata-perf-bot")
            .json(&json!({
                "body": message
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to post comment: {:?}", response.text().await?).into());
        }
    }

    Ok(())
}

pub fn format_github_message(results_text: &[String]) -> String {
    let mut formatted_message = String::new();

    for line in results_text {
        formatted_message.push_str(&line.replace('*', "**"));
        formatted_message.push('\n');
    }

    formatted_message
}
