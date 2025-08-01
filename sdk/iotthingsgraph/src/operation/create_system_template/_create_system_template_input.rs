// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSystemTemplateInput {
    /// <p>The <code>DefinitionDocument</code> used to create the system.</p>
    pub definition: ::std::option::Option<crate::types::DefinitionDocument>,
    /// <p>The namespace version in which the system is to be created.</p>
    /// <p>If no value is specified, the latest version is used by default.</p>
    pub compatible_namespace_version: ::std::option::Option<i64>,
}
impl CreateSystemTemplateInput {
    /// <p>The <code>DefinitionDocument</code> used to create the system.</p>
    pub fn definition(&self) -> ::std::option::Option<&crate::types::DefinitionDocument> {
        self.definition.as_ref()
    }
    /// <p>The namespace version in which the system is to be created.</p>
    /// <p>If no value is specified, the latest version is used by default.</p>
    pub fn compatible_namespace_version(&self) -> ::std::option::Option<i64> {
        self.compatible_namespace_version
    }
}
impl CreateSystemTemplateInput {
    /// Creates a new builder-style object to manufacture [`CreateSystemTemplateInput`](crate::operation::create_system_template::CreateSystemTemplateInput).
    pub fn builder() -> crate::operation::create_system_template::builders::CreateSystemTemplateInputBuilder {
        crate::operation::create_system_template::builders::CreateSystemTemplateInputBuilder::default()
    }
}

/// A builder for [`CreateSystemTemplateInput`](crate::operation::create_system_template::CreateSystemTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSystemTemplateInputBuilder {
    pub(crate) definition: ::std::option::Option<crate::types::DefinitionDocument>,
    pub(crate) compatible_namespace_version: ::std::option::Option<i64>,
}
impl CreateSystemTemplateInputBuilder {
    /// <p>The <code>DefinitionDocument</code> used to create the system.</p>
    /// This field is required.
    pub fn definition(mut self, input: crate::types::DefinitionDocument) -> Self {
        self.definition = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>DefinitionDocument</code> used to create the system.</p>
    pub fn set_definition(mut self, input: ::std::option::Option<crate::types::DefinitionDocument>) -> Self {
        self.definition = input;
        self
    }
    /// <p>The <code>DefinitionDocument</code> used to create the system.</p>
    pub fn get_definition(&self) -> &::std::option::Option<crate::types::DefinitionDocument> {
        &self.definition
    }
    /// <p>The namespace version in which the system is to be created.</p>
    /// <p>If no value is specified, the latest version is used by default.</p>
    pub fn compatible_namespace_version(mut self, input: i64) -> Self {
        self.compatible_namespace_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The namespace version in which the system is to be created.</p>
    /// <p>If no value is specified, the latest version is used by default.</p>
    pub fn set_compatible_namespace_version(mut self, input: ::std::option::Option<i64>) -> Self {
        self.compatible_namespace_version = input;
        self
    }
    /// <p>The namespace version in which the system is to be created.</p>
    /// <p>If no value is specified, the latest version is used by default.</p>
    pub fn get_compatible_namespace_version(&self) -> &::std::option::Option<i64> {
        &self.compatible_namespace_version
    }
    /// Consumes the builder and constructs a [`CreateSystemTemplateInput`](crate::operation::create_system_template::CreateSystemTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_system_template::CreateSystemTemplateInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_system_template::CreateSystemTemplateInput {
            definition: self.definition,
            compatible_namespace_version: self.compatible_namespace_version,
        })
    }
}
