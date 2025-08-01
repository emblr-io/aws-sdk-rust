// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies whihc properties of that label should be included in the export.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExportFilterElement {
    /// <p>Each property is defined by a key-value pair, where the key is the desired output property name (e.g. "name"), and the value is an object.</p>
    pub properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ExportFilterPropertyAttributes>>,
}
impl ExportFilterElement {
    /// <p>Each property is defined by a key-value pair, where the key is the desired output property name (e.g. "name"), and the value is an object.</p>
    pub fn properties(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::ExportFilterPropertyAttributes>> {
        self.properties.as_ref()
    }
}
impl ExportFilterElement {
    /// Creates a new builder-style object to manufacture [`ExportFilterElement`](crate::types::ExportFilterElement).
    pub fn builder() -> crate::types::builders::ExportFilterElementBuilder {
        crate::types::builders::ExportFilterElementBuilder::default()
    }
}

/// A builder for [`ExportFilterElement`](crate::types::ExportFilterElement).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExportFilterElementBuilder {
    pub(crate) properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ExportFilterPropertyAttributes>>,
}
impl ExportFilterElementBuilder {
    /// Adds a key-value pair to `properties`.
    ///
    /// To override the contents of this collection use [`set_properties`](Self::set_properties).
    ///
    /// <p>Each property is defined by a key-value pair, where the key is the desired output property name (e.g. "name"), and the value is an object.</p>
    pub fn properties(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::ExportFilterPropertyAttributes) -> Self {
        let mut hash_map = self.properties.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.properties = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Each property is defined by a key-value pair, where the key is the desired output property name (e.g. "name"), and the value is an object.</p>
    pub fn set_properties(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ExportFilterPropertyAttributes>>,
    ) -> Self {
        self.properties = input;
        self
    }
    /// <p>Each property is defined by a key-value pair, where the key is the desired output property name (e.g. "name"), and the value is an object.</p>
    pub fn get_properties(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ExportFilterPropertyAttributes>> {
        &self.properties
    }
    /// Consumes the builder and constructs a [`ExportFilterElement`](crate::types::ExportFilterElement).
    pub fn build(self) -> crate::types::ExportFilterElement {
        crate::types::ExportFilterElement { properties: self.properties }
    }
}
