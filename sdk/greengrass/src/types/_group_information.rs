// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Information about a group.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GroupInformation {
    /// The ARN of the group.
    pub arn: ::std::option::Option<::std::string::String>,
    /// The time, in milliseconds since the epoch, when the group was created.
    pub creation_timestamp: ::std::option::Option<::std::string::String>,
    /// The ID of the group.
    pub id: ::std::option::Option<::std::string::String>,
    /// The time, in milliseconds since the epoch, when the group was last updated.
    pub last_updated_timestamp: ::std::option::Option<::std::string::String>,
    /// The ID of the latest version associated with the group.
    pub latest_version: ::std::option::Option<::std::string::String>,
    /// The ARN of the latest version associated with the group.
    pub latest_version_arn: ::std::option::Option<::std::string::String>,
    /// The name of the group.
    pub name: ::std::option::Option<::std::string::String>,
}
impl GroupInformation {
    /// The ARN of the group.
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// The time, in milliseconds since the epoch, when the group was created.
    pub fn creation_timestamp(&self) -> ::std::option::Option<&str> {
        self.creation_timestamp.as_deref()
    }
    /// The ID of the group.
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// The time, in milliseconds since the epoch, when the group was last updated.
    pub fn last_updated_timestamp(&self) -> ::std::option::Option<&str> {
        self.last_updated_timestamp.as_deref()
    }
    /// The ID of the latest version associated with the group.
    pub fn latest_version(&self) -> ::std::option::Option<&str> {
        self.latest_version.as_deref()
    }
    /// The ARN of the latest version associated with the group.
    pub fn latest_version_arn(&self) -> ::std::option::Option<&str> {
        self.latest_version_arn.as_deref()
    }
    /// The name of the group.
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl GroupInformation {
    /// Creates a new builder-style object to manufacture [`GroupInformation`](crate::types::GroupInformation).
    pub fn builder() -> crate::types::builders::GroupInformationBuilder {
        crate::types::builders::GroupInformationBuilder::default()
    }
}

/// A builder for [`GroupInformation`](crate::types::GroupInformation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GroupInformationBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_timestamp: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated_timestamp: ::std::option::Option<::std::string::String>,
    pub(crate) latest_version: ::std::option::Option<::std::string::String>,
    pub(crate) latest_version_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl GroupInformationBuilder {
    /// The ARN of the group.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// The ARN of the group.
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// The ARN of the group.
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// The time, in milliseconds since the epoch, when the group was created.
    pub fn creation_timestamp(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.creation_timestamp = ::std::option::Option::Some(input.into());
        self
    }
    /// The time, in milliseconds since the epoch, when the group was created.
    pub fn set_creation_timestamp(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.creation_timestamp = input;
        self
    }
    /// The time, in milliseconds since the epoch, when the group was created.
    pub fn get_creation_timestamp(&self) -> &::std::option::Option<::std::string::String> {
        &self.creation_timestamp
    }
    /// The ID of the group.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the group.
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// The ID of the group.
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// The time, in milliseconds since the epoch, when the group was last updated.
    pub fn last_updated_timestamp(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_updated_timestamp = ::std::option::Option::Some(input.into());
        self
    }
    /// The time, in milliseconds since the epoch, when the group was last updated.
    pub fn set_last_updated_timestamp(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_updated_timestamp = input;
        self
    }
    /// The time, in milliseconds since the epoch, when the group was last updated.
    pub fn get_last_updated_timestamp(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_updated_timestamp
    }
    /// The ID of the latest version associated with the group.
    pub fn latest_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.latest_version = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the latest version associated with the group.
    pub fn set_latest_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.latest_version = input;
        self
    }
    /// The ID of the latest version associated with the group.
    pub fn get_latest_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.latest_version
    }
    /// The ARN of the latest version associated with the group.
    pub fn latest_version_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.latest_version_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// The ARN of the latest version associated with the group.
    pub fn set_latest_version_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.latest_version_arn = input;
        self
    }
    /// The ARN of the latest version associated with the group.
    pub fn get_latest_version_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.latest_version_arn
    }
    /// The name of the group.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// The name of the group.
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// The name of the group.
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`GroupInformation`](crate::types::GroupInformation).
    pub fn build(self) -> crate::types::GroupInformation {
        crate::types::GroupInformation {
            arn: self.arn,
            creation_timestamp: self.creation_timestamp,
            id: self.id,
            last_updated_timestamp: self.last_updated_timestamp,
            latest_version: self.latest_version,
            latest_version_arn: self.latest_version_arn,
            name: self.name,
        }
    }
}
