// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeProtectionGroupOutput {
    /// <p>A grouping of protected resources that you and Shield Advanced can monitor as a collective. This resource grouping improves the accuracy of detection and reduces false positives.</p>
    pub protection_group: ::std::option::Option<crate::types::ProtectionGroup>,
    _request_id: Option<String>,
}
impl DescribeProtectionGroupOutput {
    /// <p>A grouping of protected resources that you and Shield Advanced can monitor as a collective. This resource grouping improves the accuracy of detection and reduces false positives.</p>
    pub fn protection_group(&self) -> ::std::option::Option<&crate::types::ProtectionGroup> {
        self.protection_group.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeProtectionGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeProtectionGroupOutput {
    /// Creates a new builder-style object to manufacture [`DescribeProtectionGroupOutput`](crate::operation::describe_protection_group::DescribeProtectionGroupOutput).
    pub fn builder() -> crate::operation::describe_protection_group::builders::DescribeProtectionGroupOutputBuilder {
        crate::operation::describe_protection_group::builders::DescribeProtectionGroupOutputBuilder::default()
    }
}

/// A builder for [`DescribeProtectionGroupOutput`](crate::operation::describe_protection_group::DescribeProtectionGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeProtectionGroupOutputBuilder {
    pub(crate) protection_group: ::std::option::Option<crate::types::ProtectionGroup>,
    _request_id: Option<String>,
}
impl DescribeProtectionGroupOutputBuilder {
    /// <p>A grouping of protected resources that you and Shield Advanced can monitor as a collective. This resource grouping improves the accuracy of detection and reduces false positives.</p>
    /// This field is required.
    pub fn protection_group(mut self, input: crate::types::ProtectionGroup) -> Self {
        self.protection_group = ::std::option::Option::Some(input);
        self
    }
    /// <p>A grouping of protected resources that you and Shield Advanced can monitor as a collective. This resource grouping improves the accuracy of detection and reduces false positives.</p>
    pub fn set_protection_group(mut self, input: ::std::option::Option<crate::types::ProtectionGroup>) -> Self {
        self.protection_group = input;
        self
    }
    /// <p>A grouping of protected resources that you and Shield Advanced can monitor as a collective. This resource grouping improves the accuracy of detection and reduces false positives.</p>
    pub fn get_protection_group(&self) -> &::std::option::Option<crate::types::ProtectionGroup> {
        &self.protection_group
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeProtectionGroupOutput`](crate::operation::describe_protection_group::DescribeProtectionGroupOutput).
    pub fn build(self) -> crate::operation::describe_protection_group::DescribeProtectionGroupOutput {
        crate::operation::describe_protection_group::DescribeProtectionGroupOutput {
            protection_group: self.protection_group,
            _request_id: self._request_id,
        }
    }
}
