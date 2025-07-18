// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This API is in preview release for Amazon Connect and is subject to change. To request access to this API, contact Amazon Web ServicesSupport.</p>
/// <p>A summary of a given authentication profile.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AuthenticationProfileSummary {
    /// <p>The unique identifier of the authentication profile.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the authentication profile summary.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the authentication profile summary.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Shows whether the authentication profile is the default authentication profile for the Amazon Connect instance. The default authentication profile applies to all agents in an Amazon Connect instance, unless overridden by another authentication profile.</p>
    pub is_default: bool,
    /// <p>The timestamp when the authentication profile summary was last modified.</p>
    pub last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Web Services Region when the authentication profile summary was last modified.</p>
    pub last_modified_region: ::std::option::Option<::std::string::String>,
}
impl AuthenticationProfileSummary {
    /// <p>The unique identifier of the authentication profile.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the authentication profile summary.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the authentication profile summary.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Shows whether the authentication profile is the default authentication profile for the Amazon Connect instance. The default authentication profile applies to all agents in an Amazon Connect instance, unless overridden by another authentication profile.</p>
    pub fn is_default(&self) -> bool {
        self.is_default
    }
    /// <p>The timestamp when the authentication profile summary was last modified.</p>
    pub fn last_modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time.as_ref()
    }
    /// <p>The Amazon Web Services Region when the authentication profile summary was last modified.</p>
    pub fn last_modified_region(&self) -> ::std::option::Option<&str> {
        self.last_modified_region.as_deref()
    }
}
impl AuthenticationProfileSummary {
    /// Creates a new builder-style object to manufacture [`AuthenticationProfileSummary`](crate::types::AuthenticationProfileSummary).
    pub fn builder() -> crate::types::builders::AuthenticationProfileSummaryBuilder {
        crate::types::builders::AuthenticationProfileSummaryBuilder::default()
    }
}

/// A builder for [`AuthenticationProfileSummary`](crate::types::AuthenticationProfileSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AuthenticationProfileSummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) is_default: ::std::option::Option<bool>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_region: ::std::option::Option<::std::string::String>,
}
impl AuthenticationProfileSummaryBuilder {
    /// <p>The unique identifier of the authentication profile.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the authentication profile.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier of the authentication profile.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) of the authentication profile summary.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the authentication profile summary.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the authentication profile summary.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the authentication profile summary.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the authentication profile summary.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the authentication profile summary.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Shows whether the authentication profile is the default authentication profile for the Amazon Connect instance. The default authentication profile applies to all agents in an Amazon Connect instance, unless overridden by another authentication profile.</p>
    pub fn is_default(mut self, input: bool) -> Self {
        self.is_default = ::std::option::Option::Some(input);
        self
    }
    /// <p>Shows whether the authentication profile is the default authentication profile for the Amazon Connect instance. The default authentication profile applies to all agents in an Amazon Connect instance, unless overridden by another authentication profile.</p>
    pub fn set_is_default(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_default = input;
        self
    }
    /// <p>Shows whether the authentication profile is the default authentication profile for the Amazon Connect instance. The default authentication profile applies to all agents in an Amazon Connect instance, unless overridden by another authentication profile.</p>
    pub fn get_is_default(&self) -> &::std::option::Option<bool> {
        &self.is_default
    }
    /// <p>The timestamp when the authentication profile summary was last modified.</p>
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the authentication profile summary was last modified.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The timestamp when the authentication profile summary was last modified.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// <p>The Amazon Web Services Region when the authentication profile summary was last modified.</p>
    pub fn last_modified_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_modified_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Region when the authentication profile summary was last modified.</p>
    pub fn set_last_modified_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_modified_region = input;
        self
    }
    /// <p>The Amazon Web Services Region when the authentication profile summary was last modified.</p>
    pub fn get_last_modified_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_modified_region
    }
    /// Consumes the builder and constructs a [`AuthenticationProfileSummary`](crate::types::AuthenticationProfileSummary).
    pub fn build(self) -> crate::types::AuthenticationProfileSummary {
        crate::types::AuthenticationProfileSummary {
            id: self.id,
            arn: self.arn,
            name: self.name,
            is_default: self.is_default.unwrap_or_default(),
            last_modified_time: self.last_modified_time,
            last_modified_region: self.last_modified_region,
        }
    }
}
