// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAssociationOutput {
    /// <p>Information about the association.</p>
    pub association_description: ::std::option::Option<crate::types::AssociationDescription>,
    _request_id: Option<String>,
}
impl DescribeAssociationOutput {
    /// <p>Information about the association.</p>
    pub fn association_description(&self) -> ::std::option::Option<&crate::types::AssociationDescription> {
        self.association_description.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeAssociationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeAssociationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeAssociationOutput`](crate::operation::describe_association::DescribeAssociationOutput).
    pub fn builder() -> crate::operation::describe_association::builders::DescribeAssociationOutputBuilder {
        crate::operation::describe_association::builders::DescribeAssociationOutputBuilder::default()
    }
}

/// A builder for [`DescribeAssociationOutput`](crate::operation::describe_association::DescribeAssociationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAssociationOutputBuilder {
    pub(crate) association_description: ::std::option::Option<crate::types::AssociationDescription>,
    _request_id: Option<String>,
}
impl DescribeAssociationOutputBuilder {
    /// <p>Information about the association.</p>
    pub fn association_description(mut self, input: crate::types::AssociationDescription) -> Self {
        self.association_description = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the association.</p>
    pub fn set_association_description(mut self, input: ::std::option::Option<crate::types::AssociationDescription>) -> Self {
        self.association_description = input;
        self
    }
    /// <p>Information about the association.</p>
    pub fn get_association_description(&self) -> &::std::option::Option<crate::types::AssociationDescription> {
        &self.association_description
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeAssociationOutput`](crate::operation::describe_association::DescribeAssociationOutput).
    pub fn build(self) -> crate::operation::describe_association::DescribeAssociationOutput {
        crate::operation::describe_association::DescribeAssociationOutput {
            association_description: self.association_description,
            _request_id: self._request_id,
        }
    }
}
