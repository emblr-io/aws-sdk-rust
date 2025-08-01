// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Enable custom Time to Live (TTL) settings for rows and columns without setting a TTL default for the specified table.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/keyspaces/latest/devguide/TTL-how-it-works.html#ttl-howitworks_enabling">Enabling TTL on tables</a> in the <i>Amazon Keyspaces Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TimeToLive {
    /// <p>Shows how to enable custom Time to Live (TTL) settings for the specified table.</p>
    pub status: crate::types::TimeToLiveStatus,
}
impl TimeToLive {
    /// <p>Shows how to enable custom Time to Live (TTL) settings for the specified table.</p>
    pub fn status(&self) -> &crate::types::TimeToLiveStatus {
        &self.status
    }
}
impl TimeToLive {
    /// Creates a new builder-style object to manufacture [`TimeToLive`](crate::types::TimeToLive).
    pub fn builder() -> crate::types::builders::TimeToLiveBuilder {
        crate::types::builders::TimeToLiveBuilder::default()
    }
}

/// A builder for [`TimeToLive`](crate::types::TimeToLive).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TimeToLiveBuilder {
    pub(crate) status: ::std::option::Option<crate::types::TimeToLiveStatus>,
}
impl TimeToLiveBuilder {
    /// <p>Shows how to enable custom Time to Live (TTL) settings for the specified table.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::TimeToLiveStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Shows how to enable custom Time to Live (TTL) settings for the specified table.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::TimeToLiveStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Shows how to enable custom Time to Live (TTL) settings for the specified table.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::TimeToLiveStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`TimeToLive`](crate::types::TimeToLive).
    /// This method will fail if any of the following fields are not set:
    /// - [`status`](crate::types::builders::TimeToLiveBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::types::TimeToLive, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TimeToLive {
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building TimeToLive",
                )
            })?,
        })
    }
}
