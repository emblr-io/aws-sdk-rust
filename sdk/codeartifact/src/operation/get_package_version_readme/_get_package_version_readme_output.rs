// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPackageVersionReadmeOutput {
    /// <p>The format of the package with the requested readme file.</p>
    pub format: ::std::option::Option<crate::types::PackageFormat>,
    /// <p>The namespace of the package version with the requested readme file. The package component that specifies its namespace depends on its type. For example:</p>
    /// <ul>
    /// <li>
    /// <p>The namespace of a Maven package version is its <code>groupId</code>.</p></li>
    /// <li>
    /// <p>The namespace of an npm or Swift package version is its <code>scope</code>.</p></li>
    /// <li>
    /// <p>The namespace of a generic package is its <code>namespace</code>.</p></li>
    /// <li>
    /// <p>Python, NuGet, Ruby, and Cargo package versions do not contain a corresponding component, package versions of those formats do not have a namespace.</p></li>
    /// </ul>
    pub namespace: ::std::option::Option<::std::string::String>,
    /// <p>The name of the package that contains the returned readme file.</p>
    pub package: ::std::option::Option<::std::string::String>,
    /// <p>The version of the package with the requested readme file.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>The current revision associated with the package version.</p>
    pub version_revision: ::std::option::Option<::std::string::String>,
    /// <p>The text of the returned readme file.</p>
    pub readme: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetPackageVersionReadmeOutput {
    /// <p>The format of the package with the requested readme file.</p>
    pub fn format(&self) -> ::std::option::Option<&crate::types::PackageFormat> {
        self.format.as_ref()
    }
    /// <p>The namespace of the package version with the requested readme file. The package component that specifies its namespace depends on its type. For example:</p>
    /// <ul>
    /// <li>
    /// <p>The namespace of a Maven package version is its <code>groupId</code>.</p></li>
    /// <li>
    /// <p>The namespace of an npm or Swift package version is its <code>scope</code>.</p></li>
    /// <li>
    /// <p>The namespace of a generic package is its <code>namespace</code>.</p></li>
    /// <li>
    /// <p>Python, NuGet, Ruby, and Cargo package versions do not contain a corresponding component, package versions of those formats do not have a namespace.</p></li>
    /// </ul>
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
    /// <p>The name of the package that contains the returned readme file.</p>
    pub fn package(&self) -> ::std::option::Option<&str> {
        self.package.as_deref()
    }
    /// <p>The version of the package with the requested readme file.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>The current revision associated with the package version.</p>
    pub fn version_revision(&self) -> ::std::option::Option<&str> {
        self.version_revision.as_deref()
    }
    /// <p>The text of the returned readme file.</p>
    pub fn readme(&self) -> ::std::option::Option<&str> {
        self.readme.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetPackageVersionReadmeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetPackageVersionReadmeOutput {
    /// Creates a new builder-style object to manufacture [`GetPackageVersionReadmeOutput`](crate::operation::get_package_version_readme::GetPackageVersionReadmeOutput).
    pub fn builder() -> crate::operation::get_package_version_readme::builders::GetPackageVersionReadmeOutputBuilder {
        crate::operation::get_package_version_readme::builders::GetPackageVersionReadmeOutputBuilder::default()
    }
}

/// A builder for [`GetPackageVersionReadmeOutput`](crate::operation::get_package_version_readme::GetPackageVersionReadmeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPackageVersionReadmeOutputBuilder {
    pub(crate) format: ::std::option::Option<crate::types::PackageFormat>,
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
    pub(crate) package: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) version_revision: ::std::option::Option<::std::string::String>,
    pub(crate) readme: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetPackageVersionReadmeOutputBuilder {
    /// <p>The format of the package with the requested readme file.</p>
    pub fn format(mut self, input: crate::types::PackageFormat) -> Self {
        self.format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The format of the package with the requested readme file.</p>
    pub fn set_format(mut self, input: ::std::option::Option<crate::types::PackageFormat>) -> Self {
        self.format = input;
        self
    }
    /// <p>The format of the package with the requested readme file.</p>
    pub fn get_format(&self) -> &::std::option::Option<crate::types::PackageFormat> {
        &self.format
    }
    /// <p>The namespace of the package version with the requested readme file. The package component that specifies its namespace depends on its type. For example:</p>
    /// <ul>
    /// <li>
    /// <p>The namespace of a Maven package version is its <code>groupId</code>.</p></li>
    /// <li>
    /// <p>The namespace of an npm or Swift package version is its <code>scope</code>.</p></li>
    /// <li>
    /// <p>The namespace of a generic package is its <code>namespace</code>.</p></li>
    /// <li>
    /// <p>Python, NuGet, Ruby, and Cargo package versions do not contain a corresponding component, package versions of those formats do not have a namespace.</p></li>
    /// </ul>
    pub fn namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace of the package version with the requested readme file. The package component that specifies its namespace depends on its type. For example:</p>
    /// <ul>
    /// <li>
    /// <p>The namespace of a Maven package version is its <code>groupId</code>.</p></li>
    /// <li>
    /// <p>The namespace of an npm or Swift package version is its <code>scope</code>.</p></li>
    /// <li>
    /// <p>The namespace of a generic package is its <code>namespace</code>.</p></li>
    /// <li>
    /// <p>Python, NuGet, Ruby, and Cargo package versions do not contain a corresponding component, package versions of those formats do not have a namespace.</p></li>
    /// </ul>
    pub fn set_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>The namespace of the package version with the requested readme file. The package component that specifies its namespace depends on its type. For example:</p>
    /// <ul>
    /// <li>
    /// <p>The namespace of a Maven package version is its <code>groupId</code>.</p></li>
    /// <li>
    /// <p>The namespace of an npm or Swift package version is its <code>scope</code>.</p></li>
    /// <li>
    /// <p>The namespace of a generic package is its <code>namespace</code>.</p></li>
    /// <li>
    /// <p>Python, NuGet, Ruby, and Cargo package versions do not contain a corresponding component, package versions of those formats do not have a namespace.</p></li>
    /// </ul>
    pub fn get_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace
    }
    /// <p>The name of the package that contains the returned readme file.</p>
    pub fn package(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.package = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the package that contains the returned readme file.</p>
    pub fn set_package(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.package = input;
        self
    }
    /// <p>The name of the package that contains the returned readme file.</p>
    pub fn get_package(&self) -> &::std::option::Option<::std::string::String> {
        &self.package
    }
    /// <p>The version of the package with the requested readme file.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the package with the requested readme file.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the package with the requested readme file.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>The current revision associated with the package version.</p>
    pub fn version_revision(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_revision = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current revision associated with the package version.</p>
    pub fn set_version_revision(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_revision = input;
        self
    }
    /// <p>The current revision associated with the package version.</p>
    pub fn get_version_revision(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_revision
    }
    /// <p>The text of the returned readme file.</p>
    pub fn readme(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.readme = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The text of the returned readme file.</p>
    pub fn set_readme(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.readme = input;
        self
    }
    /// <p>The text of the returned readme file.</p>
    pub fn get_readme(&self) -> &::std::option::Option<::std::string::String> {
        &self.readme
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetPackageVersionReadmeOutput`](crate::operation::get_package_version_readme::GetPackageVersionReadmeOutput).
    pub fn build(self) -> crate::operation::get_package_version_readme::GetPackageVersionReadmeOutput {
        crate::operation::get_package_version_readme::GetPackageVersionReadmeOutput {
            format: self.format,
            namespace: self.namespace,
            package: self.package,
            version: self.version,
            version_revision: self.version_revision,
            readme: self.readme,
            _request_id: self._request_id,
        }
    }
}
