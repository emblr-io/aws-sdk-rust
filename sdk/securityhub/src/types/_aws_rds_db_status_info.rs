// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the status of a read replica.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsRdsDbStatusInfo {
    /// <p>The type of status. For a read replica, the status type is read replication.</p>
    pub status_type: ::std::option::Option<::std::string::String>,
    /// <p>Whether the read replica instance is operating normally.</p>
    pub normal: ::std::option::Option<bool>,
    /// <p>The status of the read replica instance.</p>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>If the read replica is currently in an error state, provides the error details.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl AwsRdsDbStatusInfo {
    /// <p>The type of status. For a read replica, the status type is read replication.</p>
    pub fn status_type(&self) -> ::std::option::Option<&str> {
        self.status_type.as_deref()
    }
    /// <p>Whether the read replica instance is operating normally.</p>
    pub fn normal(&self) -> ::std::option::Option<bool> {
        self.normal
    }
    /// <p>The status of the read replica instance.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>If the read replica is currently in an error state, provides the error details.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl AwsRdsDbStatusInfo {
    /// Creates a new builder-style object to manufacture [`AwsRdsDbStatusInfo`](crate::types::AwsRdsDbStatusInfo).
    pub fn builder() -> crate::types::builders::AwsRdsDbStatusInfoBuilder {
        crate::types::builders::AwsRdsDbStatusInfoBuilder::default()
    }
}

/// A builder for [`AwsRdsDbStatusInfo`](crate::types::AwsRdsDbStatusInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsRdsDbStatusInfoBuilder {
    pub(crate) status_type: ::std::option::Option<::std::string::String>,
    pub(crate) normal: ::std::option::Option<bool>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl AwsRdsDbStatusInfoBuilder {
    /// <p>The type of status. For a read replica, the status type is read replication.</p>
    pub fn status_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of status. For a read replica, the status type is read replication.</p>
    pub fn set_status_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_type = input;
        self
    }
    /// <p>The type of status. For a read replica, the status type is read replication.</p>
    pub fn get_status_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_type
    }
    /// <p>Whether the read replica instance is operating normally.</p>
    pub fn normal(mut self, input: bool) -> Self {
        self.normal = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether the read replica instance is operating normally.</p>
    pub fn set_normal(mut self, input: ::std::option::Option<bool>) -> Self {
        self.normal = input;
        self
    }
    /// <p>Whether the read replica instance is operating normally.</p>
    pub fn get_normal(&self) -> &::std::option::Option<bool> {
        &self.normal
    }
    /// <p>The status of the read replica instance.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the read replica instance.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the read replica instance.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>If the read replica is currently in an error state, provides the error details.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the read replica is currently in an error state, provides the error details.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>If the read replica is currently in an error state, provides the error details.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`AwsRdsDbStatusInfo`](crate::types::AwsRdsDbStatusInfo).
    pub fn build(self) -> crate::types::AwsRdsDbStatusInfo {
        crate::types::AwsRdsDbStatusInfo {
            status_type: self.status_type,
            normal: self.normal,
            status: self.status,
            message: self.message,
        }
    }
}
