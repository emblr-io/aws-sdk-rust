// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Dependency package that may be required for the project code to run.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CodegenDependency {
    /// <p>Name of the dependency package.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the version of the supported dependency package.</p>
    pub supported_version: ::std::option::Option<::std::string::String>,
    /// <p>Determines if the dependency package is using Semantic versioning. If set to true, it indicates that the dependency package uses Semantic versioning.</p>
    pub is_sem_ver: ::std::option::Option<bool>,
    /// <p>Indicates the reason to include the dependency package in your project code.</p>
    pub reason: ::std::option::Option<::std::string::String>,
}
impl CodegenDependency {
    /// <p>Name of the dependency package.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Indicates the version of the supported dependency package.</p>
    pub fn supported_version(&self) -> ::std::option::Option<&str> {
        self.supported_version.as_deref()
    }
    /// <p>Determines if the dependency package is using Semantic versioning. If set to true, it indicates that the dependency package uses Semantic versioning.</p>
    pub fn is_sem_ver(&self) -> ::std::option::Option<bool> {
        self.is_sem_ver
    }
    /// <p>Indicates the reason to include the dependency package in your project code.</p>
    pub fn reason(&self) -> ::std::option::Option<&str> {
        self.reason.as_deref()
    }
}
impl CodegenDependency {
    /// Creates a new builder-style object to manufacture [`CodegenDependency`](crate::types::CodegenDependency).
    pub fn builder() -> crate::types::builders::CodegenDependencyBuilder {
        crate::types::builders::CodegenDependencyBuilder::default()
    }
}

/// A builder for [`CodegenDependency`](crate::types::CodegenDependency).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CodegenDependencyBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) supported_version: ::std::option::Option<::std::string::String>,
    pub(crate) is_sem_ver: ::std::option::Option<bool>,
    pub(crate) reason: ::std::option::Option<::std::string::String>,
}
impl CodegenDependencyBuilder {
    /// <p>Name of the dependency package.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the dependency package.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name of the dependency package.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Indicates the version of the supported dependency package.</p>
    pub fn supported_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.supported_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates the version of the supported dependency package.</p>
    pub fn set_supported_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.supported_version = input;
        self
    }
    /// <p>Indicates the version of the supported dependency package.</p>
    pub fn get_supported_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.supported_version
    }
    /// <p>Determines if the dependency package is using Semantic versioning. If set to true, it indicates that the dependency package uses Semantic versioning.</p>
    pub fn is_sem_ver(mut self, input: bool) -> Self {
        self.is_sem_ver = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines if the dependency package is using Semantic versioning. If set to true, it indicates that the dependency package uses Semantic versioning.</p>
    pub fn set_is_sem_ver(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_sem_ver = input;
        self
    }
    /// <p>Determines if the dependency package is using Semantic versioning. If set to true, it indicates that the dependency package uses Semantic versioning.</p>
    pub fn get_is_sem_ver(&self) -> &::std::option::Option<bool> {
        &self.is_sem_ver
    }
    /// <p>Indicates the reason to include the dependency package in your project code.</p>
    pub fn reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates the reason to include the dependency package in your project code.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reason = input;
        self
    }
    /// <p>Indicates the reason to include the dependency package in your project code.</p>
    pub fn get_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.reason
    }
    /// Consumes the builder and constructs a [`CodegenDependency`](crate::types::CodegenDependency).
    pub fn build(self) -> crate::types::CodegenDependency {
        crate::types::CodegenDependency {
            name: self.name,
            supported_version: self.supported_version,
            is_sem_ver: self.is_sem_ver,
            reason: self.reason,
        }
    }
}
