// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Updates an existing VpcLink of a specified identifier.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateVpcLinkInput {
    /// <p>The identifier of the VpcLink. It is used in an Integration to reference this VpcLink.</p>
    pub vpc_link_id: ::std::option::Option<::std::string::String>,
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub patch_operations: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>,
}
impl UpdateVpcLinkInput {
    /// <p>The identifier of the VpcLink. It is used in an Integration to reference this VpcLink.</p>
    pub fn vpc_link_id(&self) -> ::std::option::Option<&str> {
        self.vpc_link_id.as_deref()
    }
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.patch_operations.is_none()`.
    pub fn patch_operations(&self) -> &[crate::types::PatchOperation] {
        self.patch_operations.as_deref().unwrap_or_default()
    }
}
impl UpdateVpcLinkInput {
    /// Creates a new builder-style object to manufacture [`UpdateVpcLinkInput`](crate::operation::update_vpc_link::UpdateVpcLinkInput).
    pub fn builder() -> crate::operation::update_vpc_link::builders::UpdateVpcLinkInputBuilder {
        crate::operation::update_vpc_link::builders::UpdateVpcLinkInputBuilder::default()
    }
}

/// A builder for [`UpdateVpcLinkInput`](crate::operation::update_vpc_link::UpdateVpcLinkInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateVpcLinkInputBuilder {
    pub(crate) vpc_link_id: ::std::option::Option<::std::string::String>,
    pub(crate) patch_operations: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>,
}
impl UpdateVpcLinkInputBuilder {
    /// <p>The identifier of the VpcLink. It is used in an Integration to reference this VpcLink.</p>
    /// This field is required.
    pub fn vpc_link_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_link_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the VpcLink. It is used in an Integration to reference this VpcLink.</p>
    pub fn set_vpc_link_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_link_id = input;
        self
    }
    /// <p>The identifier of the VpcLink. It is used in an Integration to reference this VpcLink.</p>
    pub fn get_vpc_link_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_link_id
    }
    /// Appends an item to `patch_operations`.
    ///
    /// To override the contents of this collection use [`set_patch_operations`](Self::set_patch_operations).
    ///
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub fn patch_operations(mut self, input: crate::types::PatchOperation) -> Self {
        let mut v = self.patch_operations.unwrap_or_default();
        v.push(input);
        self.patch_operations = ::std::option::Option::Some(v);
        self
    }
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub fn set_patch_operations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>) -> Self {
        self.patch_operations = input;
        self
    }
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub fn get_patch_operations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>> {
        &self.patch_operations
    }
    /// Consumes the builder and constructs a [`UpdateVpcLinkInput`](crate::operation::update_vpc_link::UpdateVpcLinkInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_vpc_link::UpdateVpcLinkInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_vpc_link::UpdateVpcLinkInput {
            vpc_link_id: self.vpc_link_id,
            patch_operations: self.patch_operations,
        })
    }
}
