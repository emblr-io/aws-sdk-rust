// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon Chime chat room details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct Room {
    /// <p>The room ID.</p>
    pub room_id: ::std::option::Option<::std::string::String>,
    /// <p>The room name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Chime account ID.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the room creator.</p>
    pub created_by: ::std::option::Option<::std::string::String>,
    /// <p>The room creation timestamp, in ISO 8601 format.</p>
    pub created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The room update timestamp, in ISO 8601 format.</p>
    pub updated_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl Room {
    /// <p>The room ID.</p>
    pub fn room_id(&self) -> ::std::option::Option<&str> {
        self.room_id.as_deref()
    }
    /// <p>The room name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Amazon Chime account ID.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The identifier of the room creator.</p>
    pub fn created_by(&self) -> ::std::option::Option<&str> {
        self.created_by.as_deref()
    }
    /// <p>The room creation timestamp, in ISO 8601 format.</p>
    pub fn created_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_timestamp.as_ref()
    }
    /// <p>The room update timestamp, in ISO 8601 format.</p>
    pub fn updated_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_timestamp.as_ref()
    }
}
impl ::std::fmt::Debug for Room {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("Room");
        formatter.field("room_id", &self.room_id);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("account_id", &self.account_id);
        formatter.field("created_by", &self.created_by);
        formatter.field("created_timestamp", &self.created_timestamp);
        formatter.field("updated_timestamp", &self.updated_timestamp);
        formatter.finish()
    }
}
impl Room {
    /// Creates a new builder-style object to manufacture [`Room`](crate::types::Room).
    pub fn builder() -> crate::types::builders::RoomBuilder {
        crate::types::builders::RoomBuilder::default()
    }
}

/// A builder for [`Room`](crate::types::Room).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct RoomBuilder {
    pub(crate) room_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl RoomBuilder {
    /// <p>The room ID.</p>
    pub fn room_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.room_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The room ID.</p>
    pub fn set_room_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.room_id = input;
        self
    }
    /// <p>The room ID.</p>
    pub fn get_room_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.room_id
    }
    /// <p>The room name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The room name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The room name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Chime account ID.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Chime account ID.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Chime account ID.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The identifier of the room creator.</p>
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the room creator.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The identifier of the room creator.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The room creation timestamp, in ISO 8601 format.</p>
    pub fn created_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The room creation timestamp, in ISO 8601 format.</p>
    pub fn set_created_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_timestamp = input;
        self
    }
    /// <p>The room creation timestamp, in ISO 8601 format.</p>
    pub fn get_created_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_timestamp
    }
    /// <p>The room update timestamp, in ISO 8601 format.</p>
    pub fn updated_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The room update timestamp, in ISO 8601 format.</p>
    pub fn set_updated_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_timestamp = input;
        self
    }
    /// <p>The room update timestamp, in ISO 8601 format.</p>
    pub fn get_updated_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_timestamp
    }
    /// Consumes the builder and constructs a [`Room`](crate::types::Room).
    pub fn build(self) -> crate::types::Room {
        crate::types::Room {
            room_id: self.room_id,
            name: self.name,
            account_id: self.account_id,
            created_by: self.created_by,
            created_timestamp: self.created_timestamp,
            updated_timestamp: self.updated_timestamp,
        }
    }
}
impl ::std::fmt::Debug for RoomBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RoomBuilder");
        formatter.field("room_id", &self.room_id);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("account_id", &self.account_id);
        formatter.field("created_by", &self.created_by);
        formatter.field("created_timestamp", &self.created_timestamp);
        formatter.field("updated_timestamp", &self.updated_timestamp);
        formatter.finish()
    }
}
