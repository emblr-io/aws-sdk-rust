// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a software package.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SoftwarePackage {
    /// <p>The name of the software package.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The version of the software package.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>The epoch of the software package.</p>
    pub epoch: ::std::option::Option<::std::string::String>,
    /// <p>The release of the software package.</p>
    pub release: ::std::option::Option<::std::string::String>,
    /// <p>The architecture used for the software package.</p>
    pub architecture: ::std::option::Option<::std::string::String>,
    /// <p>The source of the package.</p>
    pub package_manager: ::std::option::Option<::std::string::String>,
    /// <p>The file system path to the package manager inventory file.</p>
    pub file_path: ::std::option::Option<::std::string::String>,
    /// <p>The version of the software package in which the vulnerability has been resolved.</p>
    pub fixed_in_version: ::std::option::Option<::std::string::String>,
    /// <p>Describes the actions a customer can take to resolve the vulnerability in the software package.</p>
    pub remediation: ::std::option::Option<::std::string::String>,
    /// <p>The source layer hash of the vulnerable package.</p>
    pub source_layer_hash: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the source layer.</p>
    pub source_layer_arn: ::std::option::Option<::std::string::String>,
}
impl SoftwarePackage {
    /// <p>The name of the software package.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The version of the software package.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>The epoch of the software package.</p>
    pub fn epoch(&self) -> ::std::option::Option<&str> {
        self.epoch.as_deref()
    }
    /// <p>The release of the software package.</p>
    pub fn release(&self) -> ::std::option::Option<&str> {
        self.release.as_deref()
    }
    /// <p>The architecture used for the software package.</p>
    pub fn architecture(&self) -> ::std::option::Option<&str> {
        self.architecture.as_deref()
    }
    /// <p>The source of the package.</p>
    pub fn package_manager(&self) -> ::std::option::Option<&str> {
        self.package_manager.as_deref()
    }
    /// <p>The file system path to the package manager inventory file.</p>
    pub fn file_path(&self) -> ::std::option::Option<&str> {
        self.file_path.as_deref()
    }
    /// <p>The version of the software package in which the vulnerability has been resolved.</p>
    pub fn fixed_in_version(&self) -> ::std::option::Option<&str> {
        self.fixed_in_version.as_deref()
    }
    /// <p>Describes the actions a customer can take to resolve the vulnerability in the software package.</p>
    pub fn remediation(&self) -> ::std::option::Option<&str> {
        self.remediation.as_deref()
    }
    /// <p>The source layer hash of the vulnerable package.</p>
    pub fn source_layer_hash(&self) -> ::std::option::Option<&str> {
        self.source_layer_hash.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the source layer.</p>
    pub fn source_layer_arn(&self) -> ::std::option::Option<&str> {
        self.source_layer_arn.as_deref()
    }
}
impl SoftwarePackage {
    /// Creates a new builder-style object to manufacture [`SoftwarePackage`](crate::types::SoftwarePackage).
    pub fn builder() -> crate::types::builders::SoftwarePackageBuilder {
        crate::types::builders::SoftwarePackageBuilder::default()
    }
}

/// A builder for [`SoftwarePackage`](crate::types::SoftwarePackage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SoftwarePackageBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) epoch: ::std::option::Option<::std::string::String>,
    pub(crate) release: ::std::option::Option<::std::string::String>,
    pub(crate) architecture: ::std::option::Option<::std::string::String>,
    pub(crate) package_manager: ::std::option::Option<::std::string::String>,
    pub(crate) file_path: ::std::option::Option<::std::string::String>,
    pub(crate) fixed_in_version: ::std::option::Option<::std::string::String>,
    pub(crate) remediation: ::std::option::Option<::std::string::String>,
    pub(crate) source_layer_hash: ::std::option::Option<::std::string::String>,
    pub(crate) source_layer_arn: ::std::option::Option<::std::string::String>,
}
impl SoftwarePackageBuilder {
    /// <p>The name of the software package.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the software package.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the software package.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The version of the software package.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the software package.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the software package.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>The epoch of the software package.</p>
    pub fn epoch(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.epoch = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The epoch of the software package.</p>
    pub fn set_epoch(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.epoch = input;
        self
    }
    /// <p>The epoch of the software package.</p>
    pub fn get_epoch(&self) -> &::std::option::Option<::std::string::String> {
        &self.epoch
    }
    /// <p>The release of the software package.</p>
    pub fn release(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.release = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The release of the software package.</p>
    pub fn set_release(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.release = input;
        self
    }
    /// <p>The release of the software package.</p>
    pub fn get_release(&self) -> &::std::option::Option<::std::string::String> {
        &self.release
    }
    /// <p>The architecture used for the software package.</p>
    pub fn architecture(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.architecture = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The architecture used for the software package.</p>
    pub fn set_architecture(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.architecture = input;
        self
    }
    /// <p>The architecture used for the software package.</p>
    pub fn get_architecture(&self) -> &::std::option::Option<::std::string::String> {
        &self.architecture
    }
    /// <p>The source of the package.</p>
    pub fn package_manager(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.package_manager = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source of the package.</p>
    pub fn set_package_manager(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.package_manager = input;
        self
    }
    /// <p>The source of the package.</p>
    pub fn get_package_manager(&self) -> &::std::option::Option<::std::string::String> {
        &self.package_manager
    }
    /// <p>The file system path to the package manager inventory file.</p>
    pub fn file_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The file system path to the package manager inventory file.</p>
    pub fn set_file_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_path = input;
        self
    }
    /// <p>The file system path to the package manager inventory file.</p>
    pub fn get_file_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_path
    }
    /// <p>The version of the software package in which the vulnerability has been resolved.</p>
    pub fn fixed_in_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fixed_in_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the software package in which the vulnerability has been resolved.</p>
    pub fn set_fixed_in_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fixed_in_version = input;
        self
    }
    /// <p>The version of the software package in which the vulnerability has been resolved.</p>
    pub fn get_fixed_in_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.fixed_in_version
    }
    /// <p>Describes the actions a customer can take to resolve the vulnerability in the software package.</p>
    pub fn remediation(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.remediation = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Describes the actions a customer can take to resolve the vulnerability in the software package.</p>
    pub fn set_remediation(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.remediation = input;
        self
    }
    /// <p>Describes the actions a customer can take to resolve the vulnerability in the software package.</p>
    pub fn get_remediation(&self) -> &::std::option::Option<::std::string::String> {
        &self.remediation
    }
    /// <p>The source layer hash of the vulnerable package.</p>
    pub fn source_layer_hash(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_layer_hash = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source layer hash of the vulnerable package.</p>
    pub fn set_source_layer_hash(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_layer_hash = input;
        self
    }
    /// <p>The source layer hash of the vulnerable package.</p>
    pub fn get_source_layer_hash(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_layer_hash
    }
    /// <p>The Amazon Resource Name (ARN) of the source layer.</p>
    pub fn source_layer_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_layer_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the source layer.</p>
    pub fn set_source_layer_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_layer_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the source layer.</p>
    pub fn get_source_layer_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_layer_arn
    }
    /// Consumes the builder and constructs a [`SoftwarePackage`](crate::types::SoftwarePackage).
    pub fn build(self) -> crate::types::SoftwarePackage {
        crate::types::SoftwarePackage {
            name: self.name,
            version: self.version,
            epoch: self.epoch,
            release: self.release,
            architecture: self.architecture,
            package_manager: self.package_manager,
            file_path: self.file_path,
            fixed_in_version: self.fixed_in_version,
            remediation: self.remediation,
            source_layer_hash: self.source_layer_hash,
            source_layer_arn: self.source_layer_arn,
        }
    }
}
