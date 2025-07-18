// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCaseRuleOutput {
    /// <p>Unique identifier of a case rule.</p>
    pub case_rule_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of a case rule.</p>
    pub case_rule_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateCaseRuleOutput {
    /// <p>Unique identifier of a case rule.</p>
    pub fn case_rule_id(&self) -> &str {
        use std::ops::Deref;
        self.case_rule_id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of a case rule.</p>
    pub fn case_rule_arn(&self) -> &str {
        use std::ops::Deref;
        self.case_rule_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateCaseRuleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateCaseRuleOutput {
    /// Creates a new builder-style object to manufacture [`CreateCaseRuleOutput`](crate::operation::create_case_rule::CreateCaseRuleOutput).
    pub fn builder() -> crate::operation::create_case_rule::builders::CreateCaseRuleOutputBuilder {
        crate::operation::create_case_rule::builders::CreateCaseRuleOutputBuilder::default()
    }
}

/// A builder for [`CreateCaseRuleOutput`](crate::operation::create_case_rule::CreateCaseRuleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCaseRuleOutputBuilder {
    pub(crate) case_rule_id: ::std::option::Option<::std::string::String>,
    pub(crate) case_rule_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCaseRuleOutputBuilder {
    /// <p>Unique identifier of a case rule.</p>
    /// This field is required.
    pub fn case_rule_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.case_rule_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifier of a case rule.</p>
    pub fn set_case_rule_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.case_rule_id = input;
        self
    }
    /// <p>Unique identifier of a case rule.</p>
    pub fn get_case_rule_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.case_rule_id
    }
    /// <p>The Amazon Resource Name (ARN) of a case rule.</p>
    /// This field is required.
    pub fn case_rule_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.case_rule_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a case rule.</p>
    pub fn set_case_rule_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.case_rule_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a case rule.</p>
    pub fn get_case_rule_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.case_rule_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateCaseRuleOutput`](crate::operation::create_case_rule::CreateCaseRuleOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`case_rule_id`](crate::operation::create_case_rule::builders::CreateCaseRuleOutputBuilder::case_rule_id)
    /// - [`case_rule_arn`](crate::operation::create_case_rule::builders::CreateCaseRuleOutputBuilder::case_rule_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_case_rule::CreateCaseRuleOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_case_rule::CreateCaseRuleOutput {
            case_rule_id: self.case_rule_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "case_rule_id",
                    "case_rule_id was not specified but it is required when building CreateCaseRuleOutput",
                )
            })?,
            case_rule_arn: self.case_rule_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "case_rule_arn",
                    "case_rule_arn was not specified but it is required when building CreateCaseRuleOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
