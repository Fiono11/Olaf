use clap::{Parser, Subcommand};
use merlin::Transcript;
use schnorrkel::olaf::{
    simplpedpop::{round1, round2, round3, Parameters},
    Identifier,
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs::{self, File},
    io::Write,
    path::Path,
};

#[derive(Parser, Serialize, Deserialize)]
#[command(name = "app", about = "An application.", version = "1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Serialize, Deserialize)]
enum Commands {
    RunRound1 {
        #[arg(long, help = "Directory path to save the data")]
        dir_path: String,
    },
    RunRound2 {
        #[arg(long, help = "Directory path to read the data produced in round 1")]
        dir_path: String,
        #[arg(long, help = "Directory path to write the data of round 2")]
        output_dir: String,
    },
    RunRound3 {
        #[arg(long, help = "Directory path to read the data produced in round 1")]
        round1_data_dir: String,
        #[arg(long, help = "Directory path to read the data produced in round 2")]
        round2_data_dir: String,
        #[arg(long, help = "Directory path to write the data of round 3")]
        output_dir: String,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::RunRound1 { dir_path } => {
            let parameters = Parameters::new(2, 2); // Adjust parameters as necessary

            let (private_data, public_message, public_data) =
                round1::run(parameters, rand_core::OsRng).unwrap();

            // Serialize and save the public message
            let public_message_json = serde_json::to_string_pretty(&public_message)?;
            let mut public_message_file =
                File::create(Path::new(&dir_path).join("public_message.json"))?;
            public_message_file.write_all(public_message_json.as_bytes())?;

            // Serialize and save the private and public data together
            let combined_data = CombinedData {
                private_data,
                public_data,
            };
            let combined_data_json = serde_json::to_string_pretty(&combined_data)?;
            let mut combined_data_file =
                File::create(Path::new(&dir_path).join("combined_data.json"))?;
            combined_data_file.write_all(combined_data_json.as_bytes())?;

            println!("Data saved to directory {}", dir_path);
        }
        Commands::RunRound2 {
            dir_path,
            output_dir,
        } => {
            // Deserialize and read the combined private and public data
            let combined_data_json =
                fs::read_to_string(Path::new(&dir_path).join("combined_data.json"))?;
            let combined_data: CombinedData = serde_json::from_str(&combined_data_json)?;

            let message_json =
                fs::read_to_string(Path::new(&dir_path).join("received_public_messages.json"))?;
            let message: round1::PublicMessage = serde_json::from_str(&message_json)?;

            let mut messages = BTreeSet::new();
            messages.insert(message);

            let (public_data, messages) = round2::run(
                combined_data.private_data,
                &combined_data.public_data,
                messages,
                Transcript::new(b"label"),
            )
            .unwrap();

            // Serialize and save the public data to output directory
            let public_data_json = serde_json::to_string_pretty(&public_data)?;
            let mut public_data_file =
                File::create(Path::new(&output_dir).join("public_data.json"))?;
            public_data_file.write_all(public_data_json.as_bytes())?;

            // Serialize and save the messages to output directory
            let messages_json = serde_json::to_string_pretty(&messages)?;
            let mut messages_file = File::create(Path::new(&output_dir).join("messages.json"))?;
            messages_file.write_all(messages_json.as_bytes())?;

            println!("Public data and messages saved to directory {}", output_dir);
        }
        Commands::RunRound3 {
            round1_data_dir,
            round2_data_dir,
            output_dir,
        } => {
            // Deserialize and read the combined private and public data
            let combined_data_json =
                fs::read_to_string(Path::new(&round1_data_dir).join("combined_data.json"))?;
            let combined_data: CombinedData = serde_json::from_str(&combined_data_json)?;

            // Deserialize Round 2 public messages and data
            let round2_public_messages_json = fs::read_to_string(
                Path::new(&round2_data_dir).join("received_round2_public_messages.json"),
            )?;

            let round2_public_messages = serde_json::from_str(&round2_public_messages_json)?;

            let round2_private_messages_json = fs::read_to_string(
                Path::new(&round2_data_dir).join("received_round2_private_messages.json"),
            )?;
            let round2_private_messages: BTreeMap<Identifier, round2::PrivateMessage> =
                serde_json::from_str(&round2_private_messages_json)?;

            let round2_public_data_json =
                fs::read_to_string(Path::new(&round2_data_dir).join("public_data.json"))?;
            let round2_public_data: round2::PublicData =
                serde_json::from_str(&round2_public_data_json)?;

            // Run Round 3
            let result = round3::run(
                &round2_public_messages,
                &round2_public_data,
                &combined_data.public_data,
                combined_data.private_data,
                &round2_private_messages,
            )
            .unwrap();

            // Serialize and save the result of Round 3
            let output_json = serde_json::to_string_pretty(&result)?;
            let mut output_file = File::create(Path::new(&output_dir).join("round3_result.json"))?;
            output_file.write_all(output_json.as_bytes())?;
            println!("Round 3 result saved to {}", output_dir);
        }
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct CombinedData {
    private_data: round1::PrivateData,
    public_data: round1::PublicData,
}
