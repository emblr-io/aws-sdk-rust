// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateSubnetGroupOutput {
    /// <p>The subnet group that has been modified.</p>
    pub subnet_group: ::std::option::Option<crate::types::SubnetGroup>,
    _request_id: Option<String>,
}
impl UpdateSubnetGroupOutput {
    /// <p>The subnet group that has been modified.</p>
    pub fn subnet_group(&self) -> ::std::option::Option<&crate::types::SubnetGroup> {
        self.subnet_group.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateSubnetGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateSubnetGroupOutput {
    /// Creates a new builder-style object to manufacture [`UpdateSubnetGroupOutput`](crate::operation::update_subnet_group::UpdateSubnetGroupOutput).
    pub fn builder() -> crate::operation::update_subnet_group::builders::UpdateSubnetGroupOutputBuilder {
        crate::operation::update_subnet_group::builders::UpdateSubnetGroupOutputBuilder::default()
    }
}

/// A builder for [`UpdateSubnetGroupOutput`](crate::operation::update_subnet_group::UpdateSubnetGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateSubnetGroupOutputBuilder {
    pub(crate) subnet_group: ::std::option::Option<crate::types::SubnetGroup>,
    _request_id: Option<String>,
}
impl UpdateSubnetGroupOutputBuilder {
    /// <p>The subnet group that has been modified.</p>
    pub fn subnet_group(mut self, input: crate::types::SubnetGroup) -> Self {
        self.subnet_group = ::std::option::Option::Some(input);
        self
    }
    /// <p>The subnet group that has been modified.</p>
    pub fn set_subnet_group(mut self, input: ::std::option::Option<crate::types::SubnetGroup>) -> Self {
        self.subnet_group = input;
        self
    }
    /// <p>The subnet group that has been modified.</p>
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
    /// Consumes the builder and constructs a [`UpdateSubnetGroupOutput`](crate::operation::update_subnet_group::UpdateSubnetGroupOutput).
    pub fn build(self) -> crate::operation::update_subnet_group::UpdateSubnetGroupOutput {
        crate::operation::update_subnet_group::UpdateSubnetGroupOutput {
            subnet_group: self.subnet_group,
            _request_id: self._request_id,
        }
    }
}
