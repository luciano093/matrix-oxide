use std::{collections::HashMap, marker::PhantomData};

use chrono::{DateTime, TimeZone, Utc};
use url::Url;

#[derive(Debug, Clone)]
pub struct SerializableUrl(Url);

impl serde::Serialize for SerializableUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        serializer.collect_str(self.0.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct SerialiazableDateTime<T>(DateTime<T>) where T: TimeZone;

impl<T> serde::Serialize for SerialiazableDateTime<T> where T: TimeZone {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        serializer.collect_str(&self.0.timestamp_millis().to_string())
    }
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct Event {
    content: String,
    r#type: String,
}

/// Information on e2e device updates.
/// Only present on an incremental sync.
#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
pub struct DeviceLists {
    changed: String,
    left: String,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct RoomId(String);

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct Signed {
    mxid: String,
    signatures: String,
    token: String,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct Invite {
    display_name: String,
    signed: Signed,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct EventContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar_url: Option<SerializableUrl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    displayname: Option<String>, // TODO: apparently it can also be null inside the option?
    #[serde(skip_serializing_if = "Option::is_none")]
    is_direct: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    join_authorised_via_users_server: Option<String>,
    membership: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    third_party_invite: Option<Invite>
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct StrippedStateEvent {
    content: EventContent,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct InviteState {
    #[serde(skip_serializing_if = "Option::is_none")]
    events: Option<Vec<StrippedStateEvent>>,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct InvitedRoom {
    #[serde(skip_serializing_if = "Option::is_none")]
    invite_state: Option<InviteState>,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct AccountData {
    #[serde(skip_serializing_if = "Option::is_none")]
    events: Option<Vec<Event>>,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct Ephemeral {
    #[serde(skip_serializing_if = "Option::is_none")]
    events: Option<Vec<Event>>,
}

/// Tells compiler that when using recursive types, this type will never be the same as the parent type
#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct NotSame<T>(PhantomData<T>);

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct UnsignedData {
    #[serde(skip_serializing_if = "Option::is_none")]
    age: Option<SerialiazableDateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    membership: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_content: Option<EventContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redacted_because: Option<NotSame<ClientEventWithoutRoomId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_id: Option<String>,
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize)]
pub struct ClientEventWithoutRoomId {
    content: String,
    event_id: String,
    origin_server_ts: SerialiazableDateTime<Utc>,
    sender: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_key: Option<String>,
    r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    unsigned: Option<UnsignedData>,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct State {
    #[serde(skip_serializing_if = "Option::is_none")]
    events: Option<Vec<ClientEventWithoutRoomId>>
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct RoomSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    m_heroes: Option<Vec<String>>,
    // can be skipped during sync if this field hasn't changed
    m_invited_member_count: u32,
    // can be skipped during sync if this field hasn't changed
    m_joined_member_count: u32,

}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct Timeline {
    events: Vec<ClientEventWithoutRoomId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limited: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_hatch: Option<String>,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct UnreadNotificationCounts {
    #[serde(skip_serializing_if = "Option::is_none")]
    highlight_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notification_count: Option<u32>,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct EventId(String);

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct ThreadNotificationCounts {
    #[serde(skip_serializing_if = "Option::is_none")]
    highlight_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notification_count: Option<u32>,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct JoinedRoom {
    #[serde(skip_serializing_if = "Option::is_none")]
    account_data: Option<AccountData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ephemeral: Option<Ephemeral>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<State>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<RoomSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeline: Option<Timeline>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unread_notifications: Option<UnreadNotificationCounts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unread_thread_notifciations: Option<HashMap<EventId, ThreadNotificationCounts>>,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct KnockState {
    #[serde(skip_serializing_if = "Option::is_none")]
    events: Option<Vec<StrippedStateEvent>>,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct KnockedRoom {
    #[serde(skip_serializing_if = "Option::is_none")]
    knock_state: Option<KnockState>,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct LeftRoom {
    #[serde(skip_serializing_if = "Option::is_none")]
    account_data: Option<AccountData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<State>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeline: Option<Timeline>,
}

/// Updates to rooms.
#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct Rooms {
    #[serde(skip_serializing_if = "Option::is_none")]
    invite: Option<HashMap<RoomId, InvitedRoom>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    join: Option<HashMap<RoomId, JoinedRoom>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    knock: Option<HashMap<RoomId, KnockedRoom>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    leave: Option<HashMap<RoomId, LeftRoom>>,
}

#[derive(Debug, Default, Clone)]
#[derive(serde::Serialize)]
pub struct Sync {
    #[serde(skip_serializing_if = "Option::is_none")]
    account_data: Option<Vec<Event>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    device_lists: Option<DeviceLists>,

    #[serde(skip_serializing_if = "Option::is_none")]
    device_one_time_keys_count: Option<u32>,
    next_batch: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    presence: Option<Vec<Event>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    rooms: Option<Rooms>,
}

impl Sync {
    pub const fn new(
        account_data: Option<Vec<Event>>,
        device_lists: Option<DeviceLists>,
        device_one_time_keys_count: Option<u32>,
        next_batch: String,
        presence: Option<Vec<Event>>,
        rooms: Option<Rooms>,
    ) -> Self {
        Self {
            account_data,
            device_lists,
            device_one_time_keys_count,
            next_batch: next_batch,
            presence,
            rooms,
        }
    }

    pub const fn account_data(&self) -> Option<&Vec<Event>> {
        self.account_data.as_ref()
    }

    pub const fn device_lists(&self) -> Option<&DeviceLists> {
        self.device_lists.as_ref()
    }

    pub const fn device_one_time_keys_count(&self) -> Option<u32> {
        self.device_one_time_keys_count
    }

    pub const fn next_batch(&self) -> &String {
        &self.next_batch
    }

    pub const fn presence(&self) -> Option<&Vec<Event>> {
        self.presence.as_ref()
    }

    pub const fn rooms(&self) -> Option<&Rooms> {
        self.rooms.as_ref()
    }
}
