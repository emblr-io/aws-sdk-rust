// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon Chime SDK attendee fields to create, used with the BatchCreateAttendee action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateAttendeeRequestItem {
    /// <p>The Amazon Chime SDK external user ID. An idempotency token. Links the attendee to an identity managed by a builder application.</p>
    /// <p>Pattern: <code>\[-_&amp;@+=,(){}\\[\\]\/«».:|'"#a-zA-Z0-9À-ÿ\s\]*</code></p>
    /// <p>Values that begin with <code>aws:</code> are reserved. You can't configure a value that uses this prefix. Case insensitive.</p>
    pub external_user_id: ::std::string::String,
    /// <p>A list of one or more capabilities.</p>
    pub capabilities: ::std::option::Option<crate::types::AttendeeCapabilities>,
}
impl CreateAttendeeRequestItem {
    /// <p>The Amazon Chime SDK external user ID. An idempotency token. Links the attendee to an identity managed by a builder application.</p>
    /// <p>Pattern: <code>\[-_&amp;@+=,(){}\\[\\]\/«».:|'"#a-zA-Z0-9À-ÿ\s\]*</code></p>
    /// <p>Values that begin with <code>aws:</code> are reserved. You can't configure a value that uses this prefix. Case insensitive.</p>
    pub fn external_user_id(&self) -> &str {
        use std::ops::Deref;
        self.external_user_id.deref()
    }
    /// <p>A list of one or more capabilities.</p>
    pub fn capabilities(&self) -> ::std::option::Option<&crate::types::AttendeeCapabilities> {
        self.capabilities.as_ref()
    }
}
impl ::std::fmt::Debug for CreateAttendeeRequestItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateAttendeeRequestItem");
        formatter.field("external_user_id", &"*** Sensitive Data Redacted ***");
        formatter.field("capabilities", &self.capabilities);
        formatter.finish()
    }
}
impl CreateAttendeeRequestItem {
    /// Creates a new builder-style object to manufacture [`CreateAttendeeRequestItem`](crate::types::CreateAttendeeRequestItem).
    pub fn builder() -> crate::types::builders::CreateAttendeeRequestItemBuilder {
        crate::types::builders::CreateAttendeeRequestItemBuilder::default()
    }
}

/// A builder for [`CreateAttendeeRequestItem`](crate::types::CreateAttendeeRequestItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateAttendeeRequestItemBuilder {
    pub(crate) external_user_id: ::std::option::Option<::std::string::String>,
    pub(crate) capabilities: ::std::option::Option<crate::types::AttendeeCapabilities>,
}
impl CreateAttendeeRequestItemBuilder {
    /// <p>The Amazon Chime SDK external user ID. An idempotency token. Links the attendee to an identity managed by a builder application.</p>
    /// <p>Pattern: <code>\[-_&amp;@+=,(){}\\[\\]\/«».:|'"#a-zA-Z0-9À-ÿ\s\]*</code></p>
    /// <p>Values that begin with <code>aws:</code> are reserved. You can't configure a value that uses this prefix. Case insensitive.</p>
    /// This field is required.
    pub fn external_user_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.external_user_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Chime SDK external user ID. An idempotency token. Links the attendee to an identity managed by a builder application.</p>
    /// <p>Pattern: <code>\[-_&amp;@+=,(){}\\[\\]\/«».:|'"#a-zA-Z0-9À-ÿ\s\]*</code></p>
    /// <p>Values that begin with <code>aws:</code> are reserved. You can't configure a value that uses this prefix. Case insensitive.</p>
    pub fn set_external_user_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.external_user_id = input;
        self
    }
    /// <p>The Amazon Chime SDK external user ID. An idempotency token. Links the attendee to an identity managed by a builder application.</p>
    /// <p>Pattern: <code>\[-_&amp;@+=,(){}\\[\\]\/«».:|'"#a-zA-Z0-9À-ÿ\s\]*</code></p>
    /// <p>Values that begin with <code>aws:</code> are reserved. You can't configure a value that uses this prefix. Case insensitive.</p>
    pub fn get_external_user_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.external_user_id
    }
    /// <p>A list of one or more capabilities.</p>
    pub fn capabilities(mut self, input: crate::types::AttendeeCapabilities) -> Self {
        self.capabilities = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of one or more capabilities.</p>
    pub fn set_capabilities(mut self, input: ::std::option::Option<crate::types::AttendeeCapabilities>) -> Self {
        self.capabilities = input;
        self
    }
    /// <p>A list of one or more capabilities.</p>
    pub fn get_capabilities(&self) -> &::std::option::Option<crate::types::AttendeeCapabilities> {
        &self.capabilities
    }
    /// Consumes the builder and constructs a [`CreateAttendeeRequestItem`](crate::types::CreateAttendeeRequestItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`external_user_id`](crate::types::builders::CreateAttendeeRequestItemBuilder::external_user_id)
    pub fn build(self) -> ::std::result::Result<crate::types::CreateAttendeeRequestItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CreateAttendeeRequestItem {
            external_user_id: self.external_user_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "external_user_id",
                    "external_user_id was not specified but it is required when building CreateAttendeeRequestItem",
                )
            })?,
            capabilities: self.capabilities,
        })
    }
}
impl ::std::fmt::Debug for CreateAttendeeRequestItemBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateAttendeeRequestItemBuilder");
        formatter.field("external_user_id", &"*** Sensitive Data Redacted ***");
        formatter.field("capabilities", &self.capabilities);
        formatter.finish()
    }
}
