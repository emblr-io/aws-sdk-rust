// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCoipPoolInput {
    /// <p>The ID of the local gateway route table.</p>
    pub local_gateway_route_table_id: ::std::option::Option<::std::string::String>,
    /// <p>The tags to assign to the CoIP address pool.</p>
    pub tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl CreateCoipPoolInput {
    /// <p>The ID of the local gateway route table.</p>
    pub fn local_gateway_route_table_id(&self) -> ::std::option::Option<&str> {
        self.local_gateway_route_table_id.as_deref()
    }
    /// <p>The tags to assign to the CoIP address pool.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_specifications.is_none()`.
    pub fn tag_specifications(&self) -> &[crate::types::TagSpecification] {
        self.tag_specifications.as_deref().unwrap_or_default()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl CreateCoipPoolInput {
    /// Creates a new builder-style object to manufacture [`CreateCoipPoolInput`](crate::operation::create_coip_pool::CreateCoipPoolInput).
    pub fn builder() -> crate::operation::create_coip_pool::builders::CreateCoipPoolInputBuilder {
        crate::operation::create_coip_pool::builders::CreateCoipPoolInputBuilder::default()
    }
}

/// A builder for [`CreateCoipPoolInput`](crate::operation::create_coip_pool::CreateCoipPoolInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCoipPoolInputBuilder {
    pub(crate) local_gateway_route_table_id: ::std::option::Option<::std::string::String>,
    pub(crate) tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl CreateCoipPoolInputBuilder {
    /// <p>The ID of the local gateway route table.</p>
    /// This field is required.
    pub fn local_gateway_route_table_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.local_gateway_route_table_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the local gateway route table.</p>
    pub fn set_local_gateway_route_table_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.local_gateway_route_table_id = input;
        self
    }
    /// <p>The ID of the local gateway route table.</p>
    pub fn get_local_gateway_route_table_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.local_gateway_route_table_id
    }
    /// Appends an item to `tag_specifications`.
    ///
    /// To override the contents of this collection use [`set_tag_specifications`](Self::set_tag_specifications).
    ///
    /// <p>The tags to assign to the CoIP address pool.</p>
    pub fn tag_specifications(mut self, input: crate::types::TagSpecification) -> Self {
        let mut v = self.tag_specifications.unwrap_or_default();
        v.push(input);
        self.tag_specifications = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags to assign to the CoIP address pool.</p>
    pub fn set_tag_specifications(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>) -> Self {
        self.tag_specifications = input;
        self
    }
    /// <p>The tags to assign to the CoIP address pool.</p>
    pub fn get_tag_specifications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>> {
        &self.tag_specifications
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Consumes the builder and constructs a [`CreateCoipPoolInput`](crate::operation::create_coip_pool::CreateCoipPoolInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_coip_pool::CreateCoipPoolInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_coip_pool::CreateCoipPoolInput {
            local_gateway_route_table_id: self.local_gateway_route_table_id,
            tag_specifications: self.tag_specifications,
            dry_run: self.dry_run,
        })
    }
}
