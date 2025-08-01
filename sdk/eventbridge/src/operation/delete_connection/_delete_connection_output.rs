// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteConnectionOutput {
    /// <p>The ARN of the connection that was deleted.</p>
    pub connection_arn: ::std::option::Option<::std::string::String>,
    /// <p>The state of the connection before it was deleted.</p>
    pub connection_state: ::std::option::Option<crate::types::ConnectionState>,
    /// <p>A time stamp for the time that the connection was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A time stamp for the time that the connection was last modified before it was deleted.</p>
    pub last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A time stamp for the time that the connection was last authorized before it wa deleted.</p>
    pub last_authorized_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DeleteConnectionOutput {
    /// <p>The ARN of the connection that was deleted.</p>
    pub fn connection_arn(&self) -> ::std::option::Option<&str> {
        self.connection_arn.as_deref()
    }
    /// <p>The state of the connection before it was deleted.</p>
    pub fn connection_state(&self) -> ::std::option::Option<&crate::types::ConnectionState> {
        self.connection_state.as_ref()
    }
    /// <p>A time stamp for the time that the connection was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>A time stamp for the time that the connection was last modified before it was deleted.</p>
    pub fn last_modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time.as_ref()
    }
    /// <p>A time stamp for the time that the connection was last authorized before it wa deleted.</p>
    pub fn last_authorized_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_authorized_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteConnectionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteConnectionOutput {
    /// Creates a new builder-style object to manufacture [`DeleteConnectionOutput`](crate::operation::delete_connection::DeleteConnectionOutput).
    pub fn builder() -> crate::operation::delete_connection::builders::DeleteConnectionOutputBuilder {
        crate::operation::delete_connection::builders::DeleteConnectionOutputBuilder::default()
    }
}

/// A builder for [`DeleteConnectionOutput`](crate::operation::delete_connection::DeleteConnectionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteConnectionOutputBuilder {
    pub(crate) connection_arn: ::std::option::Option<::std::string::String>,
    pub(crate) connection_state: ::std::option::Option<crate::types::ConnectionState>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_authorized_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DeleteConnectionOutputBuilder {
    /// <p>The ARN of the connection that was deleted.</p>
    pub fn connection_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the connection that was deleted.</p>
    pub fn set_connection_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_arn = input;
        self
    }
    /// <p>The ARN of the connection that was deleted.</p>
    pub fn get_connection_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_arn
    }
    /// <p>The state of the connection before it was deleted.</p>
    pub fn connection_state(mut self, input: crate::types::ConnectionState) -> Self {
        self.connection_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the connection before it was deleted.</p>
    pub fn set_connection_state(mut self, input: ::std::option::Option<crate::types::ConnectionState>) -> Self {
        self.connection_state = input;
        self
    }
    /// <p>The state of the connection before it was deleted.</p>
    pub fn get_connection_state(&self) -> &::std::option::Option<crate::types::ConnectionState> {
        &self.connection_state
    }
    /// <p>A time stamp for the time that the connection was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A time stamp for the time that the connection was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>A time stamp for the time that the connection was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>A time stamp for the time that the connection was last modified before it was deleted.</p>
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A time stamp for the time that the connection was last modified before it was deleted.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>A time stamp for the time that the connection was last modified before it was deleted.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// <p>A time stamp for the time that the connection was last authorized before it wa deleted.</p>
    pub fn last_authorized_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_authorized_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A time stamp for the time that the connection was last authorized before it wa deleted.</p>
    pub fn set_last_authorized_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_authorized_time = input;
        self
    }
    /// <p>A time stamp for the time that the connection was last authorized before it wa deleted.</p>
    pub fn get_last_authorized_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_authorized_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteConnectionOutput`](crate::operation::delete_connection::DeleteConnectionOutput).
    pub fn build(self) -> crate::operation::delete_connection::DeleteConnectionOutput {
        crate::operation::delete_connection::DeleteConnectionOutput {
            connection_arn: self.connection_arn,
            connection_state: self.connection_state,
            creation_time: self.creation_time,
            last_modified_time: self.last_modified_time,
            last_authorized_time: self.last_authorized_time,
            _request_id: self._request_id,
        }
    }
}
