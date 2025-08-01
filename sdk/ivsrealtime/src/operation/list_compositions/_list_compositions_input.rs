// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCompositionsInput {
    /// <p>Filters the Composition list to match the specified Stage ARN.</p>
    pub filter_by_stage_arn: ::std::option::Option<::std::string::String>,
    /// <p>Filters the Composition list to match the specified EncoderConfiguration attached to at least one of its output.</p>
    pub filter_by_encoder_configuration_arn: ::std::option::Option<::std::string::String>,
    /// <p>The first Composition to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Maximum number of results to return. Default: 100.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListCompositionsInput {
    /// <p>Filters the Composition list to match the specified Stage ARN.</p>
    pub fn filter_by_stage_arn(&self) -> ::std::option::Option<&str> {
        self.filter_by_stage_arn.as_deref()
    }
    /// <p>Filters the Composition list to match the specified EncoderConfiguration attached to at least one of its output.</p>
    pub fn filter_by_encoder_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.filter_by_encoder_configuration_arn.as_deref()
    }
    /// <p>The first Composition to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Maximum number of results to return. Default: 100.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListCompositionsInput {
    /// Creates a new builder-style object to manufacture [`ListCompositionsInput`](crate::operation::list_compositions::ListCompositionsInput).
    pub fn builder() -> crate::operation::list_compositions::builders::ListCompositionsInputBuilder {
        crate::operation::list_compositions::builders::ListCompositionsInputBuilder::default()
    }
}

/// A builder for [`ListCompositionsInput`](crate::operation::list_compositions::ListCompositionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCompositionsInputBuilder {
    pub(crate) filter_by_stage_arn: ::std::option::Option<::std::string::String>,
    pub(crate) filter_by_encoder_configuration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListCompositionsInputBuilder {
    /// <p>Filters the Composition list to match the specified Stage ARN.</p>
    pub fn filter_by_stage_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.filter_by_stage_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filters the Composition list to match the specified Stage ARN.</p>
    pub fn set_filter_by_stage_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.filter_by_stage_arn = input;
        self
    }
    /// <p>Filters the Composition list to match the specified Stage ARN.</p>
    pub fn get_filter_by_stage_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.filter_by_stage_arn
    }
    /// <p>Filters the Composition list to match the specified EncoderConfiguration attached to at least one of its output.</p>
    pub fn filter_by_encoder_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.filter_by_encoder_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filters the Composition list to match the specified EncoderConfiguration attached to at least one of its output.</p>
    pub fn set_filter_by_encoder_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.filter_by_encoder_configuration_arn = input;
        self
    }
    /// <p>Filters the Composition list to match the specified EncoderConfiguration attached to at least one of its output.</p>
    pub fn get_filter_by_encoder_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.filter_by_encoder_configuration_arn
    }
    /// <p>The first Composition to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The first Composition to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The first Composition to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Maximum number of results to return. Default: 100.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of results to return. Default: 100.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Maximum number of results to return. Default: 100.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListCompositionsInput`](crate::operation::list_compositions::ListCompositionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_compositions::ListCompositionsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_compositions::ListCompositionsInput {
            filter_by_stage_arn: self.filter_by_stage_arn,
            filter_by_encoder_configuration_arn: self.filter_by_encoder_configuration_arn,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
