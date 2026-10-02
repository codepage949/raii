use futures_util::stream::TryStreamExt;
use rtnetlink::{
    Handle, RouteMessageBuilder, new_connection,
    packet_route::{
        route::{RouteAttribute, RouteProtocol, RouteScope, RouteType},
        rule::RuleAction,
    },
    sys::AsyncSocket,
};
use std::net::Ipv4Addr;
use tokio::io::{self, AsyncBufReadExt, BufReader};

const TABLE_ID: u32 = 112;
const PRIORITY: u32 = 112;

async fn find_index(handle: &Handle, ifname: &String) -> Result<u32, Box<dyn std::error::Error>> {
    let mut links = handle.link().get().match_name(ifname).execute();
    let link = links
        .try_next()
        .await
        .or(Err(format!("ifname not found: {ifname}")))?
        .ok_or(format!("ifname not found: {ifname}"))?;

    Ok(link.header.index)
}

async fn pause() {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    println!("취소하려면 아무 키나 누르세요.");
    reader.read_line(&mut line).await.unwrap_or(0);
}

async fn set_routes(handle: &Handle, ifindex: u32) -> Result<(), Box<dyn std::error::Error>> {
    let filter = RouteMessageBuilder::<Ipv4Addr>::new()
        .protocol(RouteProtocol::Unspec)
        .scope(RouteScope::Universe)
        .kind(RouteType::Unspec)
        .output_interface(ifindex)
        .build();
    let mut routes = handle.route().get(filter).execute();

    while let Some(mut route) = routes.try_next().await? {
        if route.header.destination_prefix_length == 0 {
            route.header.table = TABLE_ID as u8;

            route.attributes.retain(|attr| match attr {
                RouteAttribute::Table(_) => false,
                _ => true,
            });
            route.attributes.push(RouteAttribute::Table(TABLE_ID));
            handle.route().add(route).execute().await?;
        }
    }

    Ok(())
}

async fn unset_routes(handle: &Handle) -> Result<(), Box<dyn std::error::Error>> {
    let filter = RouteMessageBuilder::<Ipv4Addr>::new()
        .protocol(RouteProtocol::Unspec)
        .scope(RouteScope::Universe)
        .kind(RouteType::Unspec)
        .table_id(TABLE_ID)
        .build();
    let mut routes = handle.route().get(filter).execute();

    while let Some(route) = routes.try_next().await? {
        handle.route().del(route).execute().await?;
    }

    Ok(())
}

async fn set_rule(handle: &Handle) -> Result<(), Box<dyn std::error::Error>> {
    handle
        .rule()
        .add()
        .v4()
        .table_id(TABLE_ID)
        .priority(PRIORITY)
        .action(RuleAction::ToTable)
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .execute()
        .await?;

    Ok(())
}

async fn unset_rule(handle: &Handle) -> Result<(), Box<dyn std::error::Error>> {
    let mut rules = handle.rule().get(rtnetlink::IpVersion::V4).execute();

    while let Some(rule) = rules.try_next().await? {
        if rule.header.table == TABLE_ID as u8 {
            handle.rule().del(rule).execute().await?;
        }
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ifname = std::env::args().nth(1).ok_or("no ifname")?;
    let (mut connection, handle, _) = new_connection()?;

    connection
        .socket_mut()
        .socket_mut()
        .set_netlink_get_strict_chk(true)?;

    tokio::spawn(connection);
    unset_routes(&handle).await?;
    unset_rule(&handle).await?;

    let ifindex = find_index(&handle, &ifname).await?;

    set_routes(&handle, ifindex).await?;
    set_rule(&handle).await?;
    pause().await;
    unset_routes(&handle).await?;
    unset_rule(&handle).await?;

    Ok(())
}
