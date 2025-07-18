// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteRegistryInput {
    /// <p>This is a wrapper structure that may contain the registry name and Amazon Resource Name (ARN).</p>
    pub registry_id: ::std::option::Option<crate::types::RegistryId>,
}
impl DeleteRegistryInput {
    /// <p>This is a wrapper structure that may contain the registry name and Amazon Resource Name (ARN).</p>
    pub fn registry_id(&self) -> ::std::option::Option<&crate::types::RegistryId> {
        self.registry_id.as_ref()
    }
}
impl DeleteRegistryInput {
    /// Creates a new builder-style object to manufacture [`DeleteRegistryInput`](crate::operation::delete_registry::DeleteRegistryInput).
    pub fn builder() -> crate::operation::delete_registry::builders::DeleteRegistryInputBuilder {
        crate::operation::delete_registry::builders::DeleteRegistryInputBuilder::default()
    }
}

/// A builder for [`DeleteRegistryInput`](crate::operation::delete_registry::DeleteRegistryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteRegistryInputBuilder {
    pub(crate) registry_id: ::std::option::Option<crate::types::RegistryId>,
}
impl DeleteRegistryInputBuilder {
    /// <p>This is a wrapper structure that may contain the registry name and Amazon Resource Name (ARN).</p>
    /// This field is required.
    pub fn registry_id(mut self, input: crate::types::RegistryId) -> Self {
        self.registry_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is a wrapper structure that may contain the registry name and Amazon Resource Name (ARN).</p>
    pub fn set_registry_id(mut self, input: ::std::option::Option<crate::types::RegistryId>) -> Self {
        self.registry_id = input;
        self
    }
    /// <p>This is a wrapper structure that may contain the registry name and Amazon Resource Name (ARN).</p>
    pub fn get_registry_id(&self) -> &::std::option::Option<crate::types::RegistryId> {
        &self.registry_id
    }
    /// Consumes the builder and constructs a [`DeleteRegistryInput`](crate::operation::delete_registry::DeleteRegistryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_registry::DeleteRegistryInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_registry::DeleteRegistryInput {
            registry_id: self.registry_id,
        })
    }
}
