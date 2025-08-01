// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSubnetGroupOutput {
    /// <p>Represents the output of a <i>CreateSubnetGroup</i> operation.</p>
    pub subnet_group: ::std::option::Option<crate::types::SubnetGroup>,
    _request_id: Option<String>,
}
impl CreateSubnetGroupOutput {
    /// <p>Represents the output of a <i>CreateSubnetGroup</i> operation.</p>
    pub fn subnet_group(&self) -> ::std::option::Option<&crate::types::SubnetGroup> {
        self.subnet_group.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateSubnetGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateSubnetGroupOutput {
    /// Creates a new builder-style object to manufacture [`CreateSubnetGroupOutput`](crate::operation::create_subnet_group::CreateSubnetGroupOutput).
    pub fn builder() -> crate::operation::create_subnet_group::builders::CreateSubnetGroupOutputBuilder {
        crate::operation::create_subnet_group::builders::CreateSubnetGroupOutputBuilder::default()
    }
}

/// A builder for [`CreateSubnetGroupOutput`](crate::operation::create_subnet_group::CreateSubnetGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSubnetGroupOutputBuilder {
    pub(crate) subnet_group: ::std::option::Option<crate::types::SubnetGroup>,
    _request_id: Option<String>,
}
impl CreateSubnetGroupOutputBuilder {
    /// <p>Represents the output of a <i>CreateSubnetGroup</i> operation.</p>
    pub fn subnet_group(mut self, input: crate::types::SubnetGroup) -> Self {
        self.subnet_group = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents the output of a <i>CreateSubnetGroup</i> operation.</p>
    pub fn set_subnet_group(mut self, input: ::std::option::Option<crate::types::SubnetGroup>) -> Self {
        self.subnet_group = input;
        self
    }
    /// <p>Represents the output of a <i>CreateSubnetGroup</i> operation.</p>
    pub fn get_subnet_group(&self) -> &::std::option::Option<crate::types::SubnetGroup> {
        &self.subnet_group
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateSubnetGroupOutput`](crate::operation::create_subnet_group::CreateSubnetGroupOutput).
    pub fn build(self) -> crate::operation::create_subnet_group::CreateSubnetGroupOutput {
        crate::operation::create_subnet_group::CreateSubnetGroupOutput {
            subnet_group: self.subnet_group,
            _request_id: self._request_id,
        }
    }
}
