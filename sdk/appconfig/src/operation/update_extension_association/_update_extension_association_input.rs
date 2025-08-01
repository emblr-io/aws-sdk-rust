// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateExtensionAssociationInput {
    /// <p>The system-generated ID for the association.</p>
    pub extension_association_id: ::std::option::Option<::std::string::String>,
    /// <p>The parameter names and values defined in the extension.</p>
    pub parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl UpdateExtensionAssociationInput {
    /// <p>The system-generated ID for the association.</p>
    pub fn extension_association_id(&self) -> ::std::option::Option<&str> {
        self.extension_association_id.as_deref()
    }
    /// <p>The parameter names and values defined in the extension.</p>
    pub fn parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.parameters.as_ref()
    }
}
impl UpdateExtensionAssociationInput {
    /// Creates a new builder-style object to manufacture [`UpdateExtensionAssociationInput`](crate::operation::update_extension_association::UpdateExtensionAssociationInput).
    pub fn builder() -> crate::operation::update_extension_association::builders::UpdateExtensionAssociationInputBuilder {
        crate::operation::update_extension_association::builders::UpdateExtensionAssociationInputBuilder::default()
    }
}

/// A builder for [`UpdateExtensionAssociationInput`](crate::operation::update_extension_association::UpdateExtensionAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateExtensionAssociationInputBuilder {
    pub(crate) extension_association_id: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl UpdateExtensionAssociationInputBuilder {
    /// <p>The system-generated ID for the association.</p>
    /// This field is required.
    pub fn extension_association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.extension_association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The system-generated ID for the association.</p>
    pub fn set_extension_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.extension_association_id = input;
        self
    }
    /// <p>The system-generated ID for the association.</p>
    pub fn get_extension_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.extension_association_id
    }
    /// Adds a key-value pair to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>The parameter names and values defined in the extension.</p>
    pub fn parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The parameter names and values defined in the extension.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The parameter names and values defined in the extension.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.parameters
    }
    /// Consumes the builder and constructs a [`UpdateExtensionAssociationInput`](crate::operation::update_extension_association::UpdateExtensionAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_extension_association::UpdateExtensionAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_extension_association::UpdateExtensionAssociationInput {
            extension_association_id: self.extension_association_id,
            parameters: self.parameters,
        })
    }
}
