// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateVirtualInterfaceInput {
    /// <p>The ID of the virtual interface.</p>
    pub virtual_interface_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the LAG or connection.</p>
    pub connection_id: ::std::option::Option<::std::string::String>,
}
impl AssociateVirtualInterfaceInput {
    /// <p>The ID of the virtual interface.</p>
    pub fn virtual_interface_id(&self) -> ::std::option::Option<&str> {
        self.virtual_interface_id.as_deref()
    }
    /// <p>The ID of the LAG or connection.</p>
    pub fn connection_id(&self) -> ::std::option::Option<&str> {
        self.connection_id.as_deref()
    }
}
impl AssociateVirtualInterfaceInput {
    /// Creates a new builder-style object to manufacture [`AssociateVirtualInterfaceInput`](crate::operation::associate_virtual_interface::AssociateVirtualInterfaceInput).
    pub fn builder() -> crate::operation::associate_virtual_interface::builders::AssociateVirtualInterfaceInputBuilder {
        crate::operation::associate_virtual_interface::builders::AssociateVirtualInterfaceInputBuilder::default()
    }
}

/// A builder for [`AssociateVirtualInterfaceInput`](crate::operation::associate_virtual_interface::AssociateVirtualInterfaceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateVirtualInterfaceInputBuilder {
    pub(crate) virtual_interface_id: ::std::option::Option<::std::string::String>,
    pub(crate) connection_id: ::std::option::Option<::std::string::String>,
}
impl AssociateVirtualInterfaceInputBuilder {
    /// <p>The ID of the virtual interface.</p>
    /// This field is required.
    pub fn virtual_interface_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_interface_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the virtual interface.</p>
    pub fn set_virtual_interface_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_interface_id = input;
        self
    }
    /// <p>The ID of the virtual interface.</p>
    pub fn get_virtual_interface_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_interface_id
    }
    /// <p>The ID of the LAG or connection.</p>
    /// This field is required.
    pub fn connection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the LAG or connection.</p>
    pub fn set_connection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_id = input;
        self
    }
    /// <p>The ID of the LAG or connection.</p>
    pub fn get_connection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_id
    }
    /// Consumes the builder and constructs a [`AssociateVirtualInterfaceInput`](crate::operation::associate_virtual_interface::AssociateVirtualInterfaceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::associate_virtual_interface::AssociateVirtualInterfaceInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::associate_virtual_interface::AssociateVirtualInterfaceInput {
            virtual_interface_id: self.virtual_interface_id,
            connection_id: self.connection_id,
        })
    }
}
