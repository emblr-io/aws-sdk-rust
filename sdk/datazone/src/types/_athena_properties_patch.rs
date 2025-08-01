// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon Athena properties patch of a connection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AthenaPropertiesPatch {
    /// <p>The Amazon Athena workgroup name of a connection.</p>
    pub workgroup_name: ::std::option::Option<::std::string::String>,
}
impl AthenaPropertiesPatch {
    /// <p>The Amazon Athena workgroup name of a connection.</p>
    pub fn workgroup_name(&self) -> ::std::option::Option<&str> {
        self.workgroup_name.as_deref()
    }
}
impl AthenaPropertiesPatch {
    /// Creates a new builder-style object to manufacture [`AthenaPropertiesPatch`](crate::types::AthenaPropertiesPatch).
    pub fn builder() -> crate::types::builders::AthenaPropertiesPatchBuilder {
        crate::types::builders::AthenaPropertiesPatchBuilder::default()
    }
}

/// A builder for [`AthenaPropertiesPatch`](crate::types::AthenaPropertiesPatch).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AthenaPropertiesPatchBuilder {
    pub(crate) workgroup_name: ::std::option::Option<::std::string::String>,
}
impl AthenaPropertiesPatchBuilder {
    /// <p>The Amazon Athena workgroup name of a connection.</p>
    pub fn workgroup_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workgroup_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Athena workgroup name of a connection.</p>
    pub fn set_workgroup_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workgroup_name = input;
        self
    }
    /// <p>The Amazon Athena workgroup name of a connection.</p>
    pub fn get_workgroup_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.workgroup_name
    }
    /// Consumes the builder and constructs a [`AthenaPropertiesPatch`](crate::types::AthenaPropertiesPatch).
    pub fn build(self) -> crate::types::AthenaPropertiesPatch {
        crate::types::AthenaPropertiesPatch {
            workgroup_name: self.workgroup_name,
        }
    }
}
