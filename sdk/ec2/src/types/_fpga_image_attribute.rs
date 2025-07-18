// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an Amazon FPGA image (AFI) attribute.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FpgaImageAttribute {
    /// <p>The ID of the AFI.</p>
    pub fpga_image_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the AFI.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the AFI.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The load permissions.</p>
    pub load_permissions: ::std::option::Option<::std::vec::Vec<crate::types::LoadPermission>>,
    /// <p>The product codes.</p>
    pub product_codes: ::std::option::Option<::std::vec::Vec<crate::types::ProductCode>>,
}
impl FpgaImageAttribute {
    /// <p>The ID of the AFI.</p>
    pub fn fpga_image_id(&self) -> ::std::option::Option<&str> {
        self.fpga_image_id.as_deref()
    }
    /// <p>The name of the AFI.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the AFI.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The load permissions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.load_permissions.is_none()`.
    pub fn load_permissions(&self) -> &[crate::types::LoadPermission] {
        self.load_permissions.as_deref().unwrap_or_default()
    }
    /// <p>The product codes.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.product_codes.is_none()`.
    pub fn product_codes(&self) -> &[crate::types::ProductCode] {
        self.product_codes.as_deref().unwrap_or_default()
    }
}
impl FpgaImageAttribute {
    /// Creates a new builder-style object to manufacture [`FpgaImageAttribute`](crate::types::FpgaImageAttribute).
    pub fn builder() -> crate::types::builders::FpgaImageAttributeBuilder {
        crate::types::builders::FpgaImageAttributeBuilder::default()
    }
}

/// A builder for [`FpgaImageAttribute`](crate::types::FpgaImageAttribute).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FpgaImageAttributeBuilder {
    pub(crate) fpga_image_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) load_permissions: ::std::option::Option<::std::vec::Vec<crate::types::LoadPermission>>,
    pub(crate) product_codes: ::std::option::Option<::std::vec::Vec<crate::types::ProductCode>>,
}
impl FpgaImageAttributeBuilder {
    /// <p>The ID of the AFI.</p>
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
    /// <p>The name of the AFI.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the AFI.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the AFI.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the AFI.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the AFI.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the AFI.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `load_permissions`.
    ///
    /// To override the contents of this collection use [`set_load_permissions`](Self::set_load_permissions).
    ///
    /// <p>The load permissions.</p>
    pub fn load_permissions(mut self, input: crate::types::LoadPermission) -> Self {
        let mut v = self.load_permissions.unwrap_or_default();
        v.push(input);
        self.load_permissions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The load permissions.</p>
    pub fn set_load_permissions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LoadPermission>>) -> Self {
        self.load_permissions = input;
        self
    }
    /// <p>The load permissions.</p>
    pub fn get_load_permissions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LoadPermission>> {
        &self.load_permissions
    }
    /// Appends an item to `product_codes`.
    ///
    /// To override the contents of this collection use [`set_product_codes`](Self::set_product_codes).
    ///
    /// <p>The product codes.</p>
    pub fn product_codes(mut self, input: crate::types::ProductCode) -> Self {
        let mut v = self.product_codes.unwrap_or_default();
        v.push(input);
        self.product_codes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The product codes.</p>
    pub fn set_product_codes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ProductCode>>) -> Self {
        self.product_codes = input;
        self
    }
    /// <p>The product codes.</p>
    pub fn get_product_codes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ProductCode>> {
        &self.product_codes
    }
    /// Consumes the builder and constructs a [`FpgaImageAttribute`](crate::types::FpgaImageAttribute).
    pub fn build(self) -> crate::types::FpgaImageAttribute {
        crate::types::FpgaImageAttribute {
            fpga_image_id: self.fpga_image_id,
            name: self.name,
            description: self.description,
            load_permissions: self.load_permissions,
            product_codes: self.product_codes,
        }
    }
}
