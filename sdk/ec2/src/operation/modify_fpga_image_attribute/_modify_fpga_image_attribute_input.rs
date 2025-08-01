// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyFpgaImageAttributeInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The ID of the AFI.</p>
    pub fpga_image_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the attribute.</p>
    pub attribute: ::std::option::Option<crate::types::FpgaImageAttributeName>,
    /// <p>The operation type.</p>
    pub operation_type: ::std::option::Option<crate::types::OperationType>,
    /// <p>The Amazon Web Services account IDs. This parameter is valid only when modifying the <code>loadPermission</code> attribute.</p>
    pub user_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The user groups. This parameter is valid only when modifying the <code>loadPermission</code> attribute.</p>
    pub user_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The product codes. After you add a product code to an AFI, it can't be removed. This parameter is valid only when modifying the <code>productCodes</code> attribute.</p>
    pub product_codes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The load permission for the AFI.</p>
    pub load_permission: ::std::option::Option<crate::types::LoadPermissionModifications>,
    /// <p>A description for the AFI.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A name for the AFI.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl ModifyFpgaImageAttributeInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The ID of the AFI.</p>
    pub fn fpga_image_id(&self) -> ::std::option::Option<&str> {
        self.fpga_image_id.as_deref()
    }
    /// <p>The name of the attribute.</p>
    pub fn attribute(&self) -> ::std::option::Option<&crate::types::FpgaImageAttributeName> {
        self.attribute.as_ref()
    }
    /// <p>The operation type.</p>
    pub fn operation_type(&self) -> ::std::option::Option<&crate::types::OperationType> {
        self.operation_type.as_ref()
    }
    /// <p>The Amazon Web Services account IDs. This parameter is valid only when modifying the <code>loadPermission</code> attribute.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_ids.is_none()`.
    pub fn user_ids(&self) -> &[::std::string::String] {
        self.user_ids.as_deref().unwrap_or_default()
    }
    /// <p>The user groups. This parameter is valid only when modifying the <code>loadPermission</code> attribute.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_groups.is_none()`.
    pub fn user_groups(&self) -> &[::std::string::String] {
        self.user_groups.as_deref().unwrap_or_default()
    }
    /// <p>The product codes. After you add a product code to an AFI, it can't be removed. This parameter is valid only when modifying the <code>productCodes</code> attribute.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.product_codes.is_none()`.
    pub fn product_codes(&self) -> &[::std::string::String] {
        self.product_codes.as_deref().unwrap_or_default()
    }
    /// <p>The load permission for the AFI.</p>
    pub fn load_permission(&self) -> ::std::option::Option<&crate::types::LoadPermissionModifications> {
        self.load_permission.as_ref()
    }
    /// <p>A description for the AFI.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A name for the AFI.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl ModifyFpgaImageAttributeInput {
    /// Creates a new builder-style object to manufacture [`ModifyFpgaImageAttributeInput`](crate::operation::modify_fpga_image_attribute::ModifyFpgaImageAttributeInput).
    pub fn builder() -> crate::operation::modify_fpga_image_attribute::builders::ModifyFpgaImageAttributeInputBuilder {
        crate::operation::modify_fpga_image_attribute::builders::ModifyFpgaImageAttributeInputBuilder::default()
    }
}

/// A builder for [`ModifyFpgaImageAttributeInput`](crate::operation::modify_fpga_image_attribute::ModifyFpgaImageAttributeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyFpgaImageAttributeInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) fpga_image_id: ::std::option::Option<::std::string::String>,
    pub(crate) attribute: ::std::option::Option<crate::types::FpgaImageAttributeName>,
    pub(crate) operation_type: ::std::option::Option<crate::types::OperationType>,
    pub(crate) user_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) user_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) product_codes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) load_permission: ::std::option::Option<crate::types::LoadPermissionModifications>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl ModifyFpgaImageAttributeInputBuilder {
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
    /// <p>The ID of the AFI.</p>
    /// This field is required.
    pub fn fpga_image_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fpga_image_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the AFI.</p>
    pub fn set_fpga_image_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fpga_image_id = input;
        self
    }
    /// <p>The ID of the AFI.</p>
    pub fn get_fpga_image_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.fpga_image_id
    }
    /// <p>The name of the attribute.</p>
    pub fn attribute(mut self, input: crate::types::FpgaImageAttributeName) -> Self {
        self.attribute = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the attribute.</p>
    pub fn set_attribute(mut self, input: ::std::option::Option<crate::types::FpgaImageAttributeName>) -> Self {
        self.attribute = input;
        self
    }
    /// <p>The name of the attribute.</p>
    pub fn get_attribute(&self) -> &::std::option::Option<crate::types::FpgaImageAttributeName> {
        &self.attribute
    }
    /// <p>The operation type.</p>
    pub fn operation_type(mut self, input: crate::types::OperationType) -> Self {
        self.operation_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation type.</p>
    pub fn set_operation_type(mut self, input: ::std::option::Option<crate::types::OperationType>) -> Self {
        self.operation_type = input;
        self
    }
    /// <p>The operation type.</p>
    pub fn get_operation_type(&self) -> &::std::option::Option<crate::types::OperationType> {
        &self.operation_type
    }
    /// Appends an item to `user_ids`.
    ///
    /// To override the contents of this collection use [`set_user_ids`](Self::set_user_ids).
    ///
    /// <p>The Amazon Web Services account IDs. This parameter is valid only when modifying the <code>loadPermission</code> attribute.</p>
    pub fn user_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.user_ids.unwrap_or_default();
        v.push(input.into());
        self.user_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Web Services account IDs. This parameter is valid only when modifying the <code>loadPermission</code> attribute.</p>
    pub fn set_user_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.user_ids = input;
        self
    }
    /// <p>The Amazon Web Services account IDs. This parameter is valid only when modifying the <code>loadPermission</code> attribute.</p>
    pub fn get_user_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.user_ids
    }
    /// Appends an item to `user_groups`.
    ///
    /// To override the contents of this collection use [`set_user_groups`](Self::set_user_groups).
    ///
    /// <p>The user groups. This parameter is valid only when modifying the <code>loadPermission</code> attribute.</p>
    pub fn user_groups(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.user_groups.unwrap_or_default();
        v.push(input.into());
        self.user_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>The user groups. This parameter is valid only when modifying the <code>loadPermission</code> attribute.</p>
    pub fn set_user_groups(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.user_groups = input;
        self
    }
    /// <p>The user groups. This parameter is valid only when modifying the <code>loadPermission</code> attribute.</p>
    pub fn get_user_groups(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.user_groups
    }
    /// Appends an item to `product_codes`.
    ///
    /// To override the contents of this collection use [`set_product_codes`](Self::set_product_codes).
    ///
    /// <p>The product codes. After you add a product code to an AFI, it can't be removed. This parameter is valid only when modifying the <code>productCodes</code> attribute.</p>
    pub fn product_codes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.product_codes.unwrap_or_default();
        v.push(input.into());
        self.product_codes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The product codes. After you add a product code to an AFI, it can't be removed. This parameter is valid only when modifying the <code>productCodes</code> attribute.</p>
    pub fn set_product_codes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.product_codes = input;
        self
    }
    /// <p>The product codes. After you add a product code to an AFI, it can't be removed. This parameter is valid only when modifying the <code>productCodes</code> attribute.</p>
    pub fn get_product_codes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.product_codes
    }
    /// <p>The load permission for the AFI.</p>
    pub fn load_permission(mut self, input: crate::types::LoadPermissionModifications) -> Self {
        self.load_permission = ::std::option::Option::Some(input);
        self
    }
    /// <p>The load permission for the AFI.</p>
    pub fn set_load_permission(mut self, input: ::std::option::Option<crate::types::LoadPermissionModifications>) -> Self {
        self.load_permission = input;
        self
    }
    /// <p>The load permission for the AFI.</p>
    pub fn get_load_permission(&self) -> &::std::option::Option<crate::types::LoadPermissionModifications> {
        &self.load_permission
    }
    /// <p>A description for the AFI.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the AFI.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the AFI.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>A name for the AFI.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the AFI.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A name for the AFI.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`ModifyFpgaImageAttributeInput`](crate::operation::modify_fpga_image_attribute::ModifyFpgaImageAttributeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_fpga_image_attribute::ModifyFpgaImageAttributeInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::modify_fpga_image_attribute::ModifyFpgaImageAttributeInput {
            dry_run: self.dry_run,
            fpga_image_id: self.fpga_image_id,
            attribute: self.attribute,
            operation_type: self.operation_type,
            user_ids: self.user_ids,
            user_groups: self.user_groups,
            product_codes: self.product_codes,
            load_permission: self.load_permission,
            description: self.description,
            name: self.name,
        })
    }
}
