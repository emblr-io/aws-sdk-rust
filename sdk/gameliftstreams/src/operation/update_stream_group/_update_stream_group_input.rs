// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateStreamGroupInput {
    /// <p>An <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a> or ID that uniquely identifies the stream group resource. Example ARN: <code>arn:aws:gameliftstreams:us-west-2:111122223333:streamgroup/sg-1AB2C3De4</code>. Example ID: <code>sg-1AB2C3De4</code>.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>A set of one or more locations and the streaming capacity for each location.</p>
    pub location_configurations: ::std::option::Option<::std::vec::Vec<crate::types::LocationConfiguration>>,
    /// <p>A descriptive label for the stream group.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl UpdateStreamGroupInput {
    /// <p>An <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a> or ID that uniquely identifies the stream group resource. Example ARN: <code>arn:aws:gameliftstreams:us-west-2:111122223333:streamgroup/sg-1AB2C3De4</code>. Example ID: <code>sg-1AB2C3De4</code>.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>A set of one or more locations and the streaming capacity for each location.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.location_configurations.is_none()`.
    pub fn location_configurations(&self) -> &[crate::types::LocationConfiguration] {
        self.location_configurations.as_deref().unwrap_or_default()
    }
    /// <p>A descriptive label for the stream group.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl UpdateStreamGroupInput {
    /// Creates a new builder-style object to manufacture [`UpdateStreamGroupInput`](crate::operation::update_stream_group::UpdateStreamGroupInput).
    pub fn builder() -> crate::operation::update_stream_group::builders::UpdateStreamGroupInputBuilder {
        crate::operation::update_stream_group::builders::UpdateStreamGroupInputBuilder::default()
    }
}

/// A builder for [`UpdateStreamGroupInput`](crate::operation::update_stream_group::UpdateStreamGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateStreamGroupInputBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) location_configurations: ::std::option::Option<::std::vec::Vec<crate::types::LocationConfiguration>>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl UpdateStreamGroupInputBuilder {
    /// <p>An <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a> or ID that uniquely identifies the stream group resource. Example ARN: <code>arn:aws:gameliftstreams:us-west-2:111122223333:streamgroup/sg-1AB2C3De4</code>. Example ID: <code>sg-1AB2C3De4</code>.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a> or ID that uniquely identifies the stream group resource. Example ARN: <code>arn:aws:gameliftstreams:us-west-2:111122223333:streamgroup/sg-1AB2C3De4</code>. Example ID: <code>sg-1AB2C3De4</code>.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>An <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a> or ID that uniquely identifies the stream group resource. Example ARN: <code>arn:aws:gameliftstreams:us-west-2:111122223333:streamgroup/sg-1AB2C3De4</code>. Example ID: <code>sg-1AB2C3De4</code>.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Appends an item to `location_configurations`.
    ///
    /// To override the contents of this collection use [`set_location_configurations`](Self::set_location_configurations).
    ///
    /// <p>A set of one or more locations and the streaming capacity for each location.</p>
    pub fn location_configurations(mut self, input: crate::types::LocationConfiguration) -> Self {
        let mut v = self.location_configurations.unwrap_or_default();
        v.push(input);
        self.location_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A set of one or more locations and the streaming capacity for each location.</p>
    pub fn set_location_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LocationConfiguration>>) -> Self {
        self.location_configurations = input;
        self
    }
    /// <p>A set of one or more locations and the streaming capacity for each location.</p>
    pub fn get_location_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LocationConfiguration>> {
        &self.location_configurations
    }
    /// <p>A descriptive label for the stream group.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A descriptive label for the stream group.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A descriptive label for the stream group.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`UpdateStreamGroupInput`](crate::operation::update_stream_group::UpdateStreamGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_stream_group::UpdateStreamGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_stream_group::UpdateStreamGroupInput {
            identifier: self.identifier,
            location_configurations: self.location_configurations,
            description: self.description,
        })
    }
}
