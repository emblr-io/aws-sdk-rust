// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Status of the Cognito options for the specified Elasticsearch domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CognitoOptionsStatus {
    /// <p>Specifies the Cognito options for the specified Elasticsearch domain.</p>
    pub options: ::std::option::Option<crate::types::CognitoOptions>,
    /// <p>Specifies the status of the Cognito options for the specified Elasticsearch domain.</p>
    pub status: ::std::option::Option<crate::types::OptionStatus>,
}
impl CognitoOptionsStatus {
    /// <p>Specifies the Cognito options for the specified Elasticsearch domain.</p>
    pub fn options(&self) -> ::std::option::Option<&crate::types::CognitoOptions> {
        self.options.as_ref()
    }
    /// <p>Specifies the status of the Cognito options for the specified Elasticsearch domain.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::OptionStatus> {
        self.status.as_ref()
    }
}
impl CognitoOptionsStatus {
    /// Creates a new builder-style object to manufacture [`CognitoOptionsStatus`](crate::types::CognitoOptionsStatus).
    pub fn builder() -> crate::types::builders::CognitoOptionsStatusBuilder {
        crate::types::builders::CognitoOptionsStatusBuilder::default()
    }
}

/// A builder for [`CognitoOptionsStatus`](crate::types::CognitoOptionsStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CognitoOptionsStatusBuilder {
    pub(crate) options: ::std::option::Option<crate::types::CognitoOptions>,
    pub(crate) status: ::std::option::Option<crate::types::OptionStatus>,
}
impl CognitoOptionsStatusBuilder {
    /// <p>Specifies the Cognito options for the specified Elasticsearch domain.</p>
    /// This field is required.
    pub fn options(mut self, input: crate::types::CognitoOptions) -> Self {
        self.options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the Cognito options for the specified Elasticsearch domain.</p>
    pub fn set_options(mut self, input: ::std::option::Option<crate::types::CognitoOptions>) -> Self {
        self.options = input;
        self
    }
    /// <p>Specifies the Cognito options for the specified Elasticsearch domain.</p>
    pub fn get_options(&self) -> &::std::option::Option<crate::types::CognitoOptions> {
        &self.options
    }
    /// <p>Specifies the status of the Cognito options for the specified Elasticsearch domain.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::OptionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the status of the Cognito options for the specified Elasticsearch domain.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::OptionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Specifies the status of the Cognito options for the specified Elasticsearch domain.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::OptionStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`CognitoOptionsStatus`](crate::types::CognitoOptionsStatus).
    pub fn build(self) -> crate::types::CognitoOptionsStatus {
        crate::types::CognitoOptionsStatus {
            options: self.options,
            status: self.status,
        }
    }
}
