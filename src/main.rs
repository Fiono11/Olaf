use clap::{Parser, Subcommand};
use curve25519_dalek::RistrettoPoint;
use merlin::Transcript;
use rand_core::OsRng;
use schnorrkel::{
    olaf::{
        frost::{
            round1::{self as frost_round1, SigningCommitments, SigningNonces},
            round2::{self as frost_round2, SignatureShare, SigningPackage},
            round3::aggregate,
        },
        identifier::Identifier,
        keys::{KeyPackage, PublicKeyPackage},
        simplpedpop::{
            round1, round2,
            round3::{self, PrivateData},
            Parameters, SecretShare,
        },
    },
    PublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    collections::{BTreeMap, BTreeSet},
    default,
    fs::{self, File},
    io::Write,
    path::Path,
};
use subxt::{
    backend::{legacy::LegacyRpcMethods, rpc::RpcClient},
    client::OnlineClientT,
    config::polkadot::PolkadotExtrinsicParamsBuilder as Params,
};
use subxt::{
    dynamic::Value,
    storage::Address,
    utils::{AccountId32, MultiAddress},
};
use subxt::{tx::SubmittableExtrinsic, OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::dev;
//use subxt_signer::sr25519::{dev, PublicKey as PK, Signature};

// Generate an interface that we can use from the node's metadata.
#[subxt::subxt(runtime_metadata_path = "metadata.scale")]
pub mod polkadot {}

const NONCE: u32 = 6;
const CONTEXT: &[u8] = b"substrate";

#[derive(Parser, Serialize, Deserialize)]
#[command(name = "app", about = "An application.", version = "1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Serialize, Deserialize)]
enum Commands {
    RunRound1Olaf {
        #[arg(long, help = "Directory path to save the data")]
        dir_path: String,
    },
    RunRound2Olaf {
        #[arg(long, help = "Directory path to read the data produced in round 1")]
        dir_path: String,
        #[arg(long, help = "Directory path to write the data of round 2")]
        output_dir: String,
    },
    RunRound3Olaf {
        #[arg(long, help = "Directory path to read the data produced in round 1")]
        round1_data_dir: String,
        #[arg(long, help = "Directory path to read the data produced in round 2")]
        round2_data_dir: String,
        #[arg(long, help = "Directory path to write the data of round 3")]
        output_dir: String,
    },
    RunRound1FROST {
        #[arg(
            long,
            help = "Directory path to read the data produced in round 3 of the Olaf protocol"
        )]
        round3_data_dir: String,
        #[arg(
            long,
            help = "Directory path to write the data of round 1 of the FROST protocol"
        )]
        output_dir: String,
    },
    RunRound2FROST {
        #[arg(
            long,
            help = "Directory path to read the data produced in round 2 of the Olaf protocol"
        )]
        round2_data_dir: String,
        #[arg(
            long,
            help = "Directory path to read the data produced in round 3 of the Olaf protocol"
        )]
        round3_data_dir: String,
        #[arg(
            long,
            help = "Directory path to read the data produced in round 1 of the FROST protocol"
        )]
        round1_frost_data_dir: String,
        #[arg(
            long,
            help = "Directory path to write the data of round 2 of the FROST protocol"
        )]
        output_dir: String,
    },
    AggregateFROST {
        #[arg(
            long,
            help = "Directory path to read the data produced in round 3 of the Olaf protocol"
        )]
        round3_data_dir: String,
        #[arg(
            long,
            help = "Directory path to read the data produced in round 1 of the FROST protocol"
        )]
        round1_frost_data_dir: String,
        #[arg(
            long,
            help = "Directory path to read the data produced in round 2 of the FROST protocol"
        )]
        round2_frost_data_dir: String,
        #[arg(
            long,
            help = "Directory path to write the data of aggregate FROST protocol"
        )]
        output_dir: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::RunRound1Olaf { dir_path } => {
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
        Commands::RunRound2Olaf {
            dir_path,
            output_dir,
        } => {
            // Deserialize and read the combined private and public data
            let combined_data_json =
                fs::read_to_string(Path::new(&dir_path).join("combined_data.json"))?;
            let combined_data: CombinedData = serde_json::from_str(&combined_data_json)?;

            let message_json = fs::read_to_string(
                Path::new(&dir_path).join("received_round1_public_messages.json"),
            )?;
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
        Commands::RunRound3Olaf {
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

            let container = Container {
                group_public_key: result.0,
                group_public_key_shares: result.1,
                private_data: result.2,
            };

            // Serialize and save the result of Round 3
            let output_json = serde_json::to_string_pretty(&container)?;

            let mut output_file = File::create(Path::new(&output_dir).join("round3_result.json"))?;

            output_file.write_all(output_json.as_bytes())?;

            println!("Round 3 result saved to {}", output_dir);
        }
        Commands::RunRound1FROST {
            round3_data_dir,
            output_dir,
        } => {
            let round3_result_json =
                fs::read_to_string(Path::new(&round3_data_dir).join("round3_result.json"))?;

            let signing_share: SecretShare =
                serde_json::from_str::<Container>(&round3_result_json)?
                    .private_data
                    .total_secret_share()
                    .clone();

            let (nonces, commitments) = frost_round1::commit(&signing_share, &mut OsRng);

            let frost_round1 = FROSTRound1 {
                nonces,
                commitments,
            };

            // Serialize and save the result of Round 1 of FROST
            let output_json = serde_json::to_string_pretty(&frost_round1)?;

            let mut output_file =
                File::create(Path::new(&output_dir).join("round1_frost_result.json"))?;

            output_file.write_all(output_json.as_bytes())?;

            println!("FROST Round 1 data saved to {}", output_dir);
        }
        Commands::RunRound2FROST {
            round2_data_dir,
            round3_data_dir,
            round1_frost_data_dir,
            output_dir,
        } => {
            let frost_round1_json = fs::read_to_string(
                Path::new(&round1_frost_data_dir).join("round1_frost_result.json"),
            )?;

            let frost_round1 = serde_json::from_str::<FROSTRound1>(&frost_round1_json)?;

            let round3_result_json =
                fs::read_to_string(Path::new(&round3_data_dir).join("round3_result.json"))?;

            let container: Container = serde_json::from_str::<Container>(&round3_result_json)?;

            let round2_public_data_json =
                fs::read_to_string(Path::new(&round2_data_dir).join("public_data.json"))?;

            let round2_public_data: round2::PublicData =
                serde_json::from_str(&round2_public_data_json)?;

            let own_identifier = round2_public_data.identifiers().own_identifier();

            let key_package = KeyPackage::new(
                *own_identifier,
                container.private_data.total_secret_share().clone(),
                *container
                    .group_public_key_shares
                    .get(&own_identifier)
                    .unwrap(),
                container.group_public_key,
                2,
            );

            let frost_round1_commitments = fs::read_to_string(
                Path::new(&round1_frost_data_dir).join("signing_commitments.json"),
            )?;

            let commitments_map = serde_json::from_str::<BTreeMap<Identifier, SigningCommitments>>(
                &frost_round1_commitments,
            )?;

            // Create client:
            let client = OnlineClient::<PolkadotConfig>::new().await?;

            let rpc_client = RpcClient::from_url("ws://127.0.0.1:9944").await?;

            let legacy_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client);

            // Create a dummy tx payload to sign:
            let call =
                subxt::dynamic::tx("System", "remark", vec![Value::from_bytes("Hello there")]);

            let account_id = AccountId32(container.group_public_key.to_bytes());

            let nonce = legacy_rpc.system_account_next_index(&account_id).await?;

            //let params = Default::default();
            let params = Params::new().nonce(nonce).build();

            // Construct the tx but don't sign it. The account nonce here defaults to 0.
            // You can use `create_partial_signed` to fetch the correct nonce.
            /*let partial_tx = client
            .tx()
            .create_partial_signed(&call, &account_id, params)
            .await?;*/

            let partial_tx = client.tx().create_partial_signed_offline(&call, params)?;

            let public_key = subxt::utils::AccountId32(container.group_public_key.to_bytes());

            /*let partial_tx = client
            .tx()
            .create_partial_signed(&call, &public_key, params)
            .await?;*/

            let payload = partial_tx.signer_payload();

            println!("payload: {:?}", payload);

            let signing_package = SigningPackage::new(commitments_map, &payload[..], CONTEXT);

            let signature_share: SignatureShare =
                frost_round2::sign(&signing_package, &frost_round1.nonces, &key_package).unwrap();

            // Serialize and save the result of Round 1 of FROST
            let output_json = serde_json::to_string_pretty(&signature_share)?;

            let mut output_file =
                File::create(Path::new(&output_dir).join("frost_round2_result.json"))?;

            output_file.write_all(output_json.as_bytes())?;

            let output_json_payload = serde_json::to_string_pretty(&payload)?;

            let mut output_file_payload =
                File::create(Path::new(&output_dir).join("payload.json"))?;

            output_file_payload.write_all(output_json_payload.as_bytes())?;

            println!("FROST Round 2 data saved to {}", output_dir);
        }
        Commands::AggregateFROST {
            round3_data_dir,
            round1_frost_data_dir,
            round2_frost_data_dir,
            output_dir,
        } => {
            let round2_signature_shares_json = fs::read_to_string(
                Path::new(&round2_frost_data_dir).join("signature_shares.json"),
            )?;

            let signature_shares = serde_json::from_str::<BTreeMap<Identifier, SignatureShare>>(
                &round2_signature_shares_json,
            )?;

            let payload_json =
                fs::read_to_string(Path::new(&round2_frost_data_dir).join("payload.json"))?;

            let payload = serde_json::from_str::<Vec<u8>>(&payload_json)?;

            let round3_result_json =
                fs::read_to_string(Path::new(&round3_data_dir).join("round3_result.json"))?;

            let container: Container = serde_json::from_str::<Container>(&round3_result_json)?;

            let pubkey_package = PublicKeyPackage::new(
                container.group_public_key_shares,
                container.group_public_key,
            );

            let frost_round1_commitments = fs::read_to_string(
                Path::new(&round1_frost_data_dir).join("signing_commitments.json"),
            )?;

            let commitments_map = serde_json::from_str::<BTreeMap<Identifier, SigningCommitments>>(
                &frost_round1_commitments,
            )?;

            // Create client:
            let client = OnlineClient::<PolkadotConfig>::new().await?;

            let rpc_client = RpcClient::from_url("ws://127.0.0.1:9944").await?;

            let legacy_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client);

            let account_id = AccountId32(container.group_public_key.to_bytes());

            let nonce = legacy_rpc.system_account_next_index(&account_id).await?;

            // Create a dummy tx payload to sign:
            let call =
                subxt::dynamic::tx("System", "remark", vec![Value::from_bytes("Hello there")]);

            //let params = Default::default();
            let params = Params::new().nonce(nonce).build();

            let account_id = AccountId32(container.group_public_key.to_bytes());

            // Construct the tx but don't sign it. The account nonce here defaults to 0.
            // You can use `create_partial_signed` to fetch the correct nonce.
            /*let partial_tx = client
            .tx()
            .create_partial_signed(&call, &account_id, params)
            .await?;*/

            let partial_tx = client.tx().create_partial_signed_offline(&call, params)?;

            let account_id = AccountId32(container.group_public_key.to_bytes());

            /*let partial_tx = client
            .tx()
            .create_partial_signed(&call, &account_id, params)
            .await?;*/

            let payload = partial_tx.signer_payload();

            println!("payload: {:?}", payload);

            //let params = Default::default();

            let signing_package = SigningPackage::new(commitments_map, &payload[..], CONTEXT);

            // Aggregate (also verifies the signature shares)
            let group_signature =
                aggregate(&signing_package, &signature_shares, &pubkey_package).unwrap();

            let signature = subxt_signer::sr25519::Signature(group_signature.to_bytes());

            //let public_key = MultiAddress::Address32(container.group_public_key.to_bytes());
            let public_key: MultiAddress<AccountId32, _> =
                subxt_signer::sr25519::PublicKey(container.group_public_key.to_bytes()).into();

            // Now we can build an tx, which one can call `submit` or `submit_and_watch`
            // on to submit to a node and optionally watch the status.
            let tx = partial_tx.sign_with_address_and_signature(&public_key, &signature.into());

            /*let tx = client
            .tx()
            .create_signed(&call, &dev::alice(), params)
            .await?;*/

            tx.submit().await?;

            //let dry_res = tx.validate().await;
            //println!("Validation Result: {:?}", dry_res);

            /*let from = dev::alice();
            let hash = client
                .tx()
                .sign_and_submit(&payload1, &from, params)
                .await?;*/

            //let ext_hash = tx.hash();

            //let sub = client.backend().submit_transaction(tx.encoded()).await?;

            //let mut progress = subxt::tx::TxProgress::new(sub, client.clone(), ext_hash);

            /*while let Some(status) = progress.next().await {
            match status? {
                // It's finalized in a block!
                subxt::tx::TxStatus::InFinalizedBlock(in_block) => {
                    println!(
                        "Transaction {:?} is finalized in block {:?}",
                        in_block.extrinsic_hash(),
                        in_block.block_hash()
                    );

                    // grab the events and fail if no ExtrinsicSuccess event seen:
                    let events = in_block.wait_for_success().await?;
                    // We can look for events (this uses the static interface; we can also iterate
                    // over them and dynamically decode them):
                    let transfer_event =
                        events.find_first::<polkadot::balances::events::Transfer>()?;

                    if let Some(event) = transfer_event {
                        println!("Balance transfer success: {event:?}");
                    } else {
                        println!("Failed to find Balances::Transfer Event");
                    }
                }
                // Just log any other status we encounter:
                other => {
                    println!("Status: {other:?}");
                }
            }
            }*/

            let output_json = serde_json::to_string_pretty(&group_signature)?;

            let mut output_file =
                File::create(Path::new(&output_dir).join("group_signature.json"))?;

            output_file.write_all(output_json.as_bytes())?;

            println!("FROST Aggregate data saved to {}", output_dir);
        }
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct CombinedData {
    private_data: round1::PrivateData,
    public_data: round1::PublicData,
}

#[derive(Serialize, Deserialize)]
struct Container {
    group_public_key: PublicKey,
    group_public_key_shares: BTreeMap<Identifier, RistrettoPoint>,
    private_data: PrivateData,
}

#[derive(Serialize, Deserialize)]
struct FROSTRound1 {
    nonces: SigningNonces,
    commitments: SigningCommitments,
}
