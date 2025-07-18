// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateLogPatternOutput {
    /// <p>The successfully created log pattern.</p>
    pub log_pattern: ::std::option::Option<crate::types::LogPattern>,
    /// <p>The name of the resource group.</p>
    pub resource_group_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateLogPatternOutput {
    /// <p>The successfully created log pattern.</p>
    pub fn log_pattern(&self) -> ::std::option::Option<&crate::types::LogPattern> {
        self.log_pattern.as_ref()
    }
    /// <p>The name of the resource group.</p>
    pub fn resource_group_name(&self) -> ::std::option::Option<&str> {
        self.resource_group_name.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateLogPatternOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateLogPatternOutput {
    /// Creates a new builder-style object to manufacture [`CreateLogPatternOutput`](crate::operation::create_log_pattern::CreateLogPatternOutput).
    pub fn builder() -> crate::operation::create_log_pattern::builders::CreateLogPatternOutputBuilder {
        crate::operation::create_log_pattern::builders::CreateLogPatternOutputBuilder::default()
    }
}

/// A builder for [`CreateLogPatternOutput`](crate::operation::create_log_pattern::CreateLogPatternOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateLogPatternOutputBuilder {
    pub(crate) log_pattern: ::std::option::Option<crate::types::LogPattern>,
    pub(crate) resource_group_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateLogPatternOutputBuilder {
    /// <p>The successfully created log pattern.</p>
    pub fn log_pattern(mut self, input: crate::types::LogPattern) -> Self {
        self.log_pattern = ::std::option::Option::Some(input);
        self
    }
    /// <p>The successfully created log pattern.</p>
    pub fn set_log_pattern(mut self, input: ::std::option::Option<crate::types::LogPattern>) -> Self {
        self.log_pattern = input;
        self
    }
    /// <p>The successfully created log pattern.</p>
    pub fn get_log_pattern(&self) -> &::std::option::Option<crate::types::LogPattern> {
        &self.log_pattern
    }
    /// <p>The name of the resource group.</p>
    pub fn resource_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the resource group.</p>
    pub fn set_resource_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_group_name = input;
        self
    }
    /// <p>The name of the resource group.</p>
    pub fn get_resource_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_group_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateLogPatternOutput`](crate::operation::create_log_pattern::CreateLogPatternOutput).
    pub fn build(self) -> crate::operation::create_log_pattern::CreateLogPatternOutput {
        crate::operation::create_log_pattern::CreateLogPatternOutput {
            log_pattern: self.log_pattern,
            resource_group_name: self.resource_group_name,
            _request_id: self._request_id,
        }
    }
}
