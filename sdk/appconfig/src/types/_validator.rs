// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A validator provides a syntactic or semantic check to ensure the configuration that you want to deploy functions as intended. To validate your application configuration data, you provide a schema or an Amazon Web Services Lambda function that runs against the configuration. The configuration deployment or update can only proceed when the configuration data is valid. For more information, see <a href="https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-configuration-profile.html#appconfig-creating-configuration-and-profile-validators">About validators</a> in the <i>AppConfig User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct Validator {
    /// <p>AppConfig supports validators of type <code>JSON_SCHEMA</code> and <code>LAMBDA</code></p>
    pub r#type: crate::types::ValidatorType,
    /// <p>Either the JSON Schema content or the Amazon Resource Name (ARN) of an Lambda function.</p>
    pub content: ::std::string::String,
}
impl Validator {
    /// <p>AppConfig supports validators of type <code>JSON_SCHEMA</code> and <code>LAMBDA</code></p>
    pub fn r#type(&self) -> &crate::types::ValidatorType {
        &self.r#type
    }
    /// <p>Either the JSON Schema content or the Amazon Resource Name (ARN) of an Lambda function.</p>
    pub fn content(&self) -> &str {
        use std::ops::Deref;
        self.content.deref()
    }
}
impl ::std::fmt::Debug for Validator {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("Validator");
        formatter.field("r#type", &self.r#type);
        formatter.field("content", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl Validator {
    /// Creates a new builder-style object to manufacture [`Validator`](crate::types::Validator).
    pub fn builder() -> crate::types::builders::ValidatorBuilder {
        crate::types::builders::ValidatorBuilder::default()
    }
}

/// A builder for [`Validator`](crate::types::Validator).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ValidatorBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::ValidatorType>,
    pub(crate) content: ::std::option::Option<::std::string::String>,
}
impl ValidatorBuilder {
    /// <p>AppConfig supports validators of type <code>JSON_SCHEMA</code> and <code>LAMBDA</code></p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::ValidatorType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>AppConfig supports validators of type <code>JSON_SCHEMA</code> and <code>LAMBDA</code></p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ValidatorType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>AppConfig supports validators of type <code>JSON_SCHEMA</code> and <code>LAMBDA</code></p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ValidatorType> {
        &self.r#type
    }
    /// <p>Either the JSON Schema content or the Amazon Resource Name (ARN) of an Lambda function.</p>
    /// This field is required.
    pub fn content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Either the JSON Schema content or the Amazon Resource Name (ARN) of an Lambda function.</p>
    pub fn set_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content = input;
        self
    }
    /// <p>Either the JSON Schema content or the Amazon Resource Name (ARN) of an Lambda function.</p>
    pub fn get_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.content
    }
    /// Consumes the builder and constructs a [`Validator`](crate::types::Validator).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::ValidatorBuilder::type)
    /// - [`content`](crate::types::builders::ValidatorBuilder::content)
    pub fn build(self) -> ::std::result::Result<crate::types::Validator, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Validator {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building Validator",
                )
            })?,
            content: self.content.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "content",
                    "content was not specified but it is required when building Validator",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for ValidatorBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ValidatorBuilder");
        formatter.field("r#type", &self.r#type);
        formatter.field("content", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
