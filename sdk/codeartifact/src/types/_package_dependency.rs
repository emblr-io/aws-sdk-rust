// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about a package dependency.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PackageDependency {
    /// <p>The namespace of the package that this package depends on. The package component that specifies its namespace depends on its type. For example:</p>
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
    /// <p>The name of the package that this package depends on.</p>
    pub package: ::std::option::Option<::std::string::String>,
    /// <p>The type of a package dependency. The possible values depend on the package type.</p>
    /// <ul>
    /// <li>
    /// <p>npm: <code>regular</code>, <code>dev</code>, <code>peer</code>, <code>optional</code></p></li>
    /// <li>
    /// <p>maven: <code>optional</code>, <code>parent</code>, <code>compile</code>, <code>runtime</code>, <code>test</code>, <code>system</code>, <code>provided</code>.</p><note>
    /// <p>Note that <code>parent</code> is not a regular Maven dependency type; instead this is extracted from the <code><parent></parent></code> element if one is defined in the package version's POM file.</p>
    /// </note></li>
    /// <li>
    /// <p>nuget: The <code>dependencyType</code> field is never set for NuGet packages.</p></li>
    /// <li>
    /// <p>pypi: <code>Requires-Dist</code></p></li>
    /// </ul>
    pub dependency_type: ::std::option::Option<::std::string::String>,
    /// <p>The required version, or version range, of the package that this package depends on. The version format is specific to the package type. For example, the following are possible valid required versions: <code>1.2.3</code>, <code>^2.3.4</code>, or <code>4.x</code>.</p>
    pub version_requirement: ::std::option::Option<::std::string::String>,
}
impl PackageDependency {
    /// <p>The namespace of the package that this package depends on. The package component that specifies its namespace depends on its type. For example:</p>
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
    /// <p>The name of the package that this package depends on.</p>
    pub fn package(&self) -> ::std::option::Option<&str> {
        self.package.as_deref()
    }
    /// <p>The type of a package dependency. The possible values depend on the package type.</p>
    /// <ul>
    /// <li>
    /// <p>npm: <code>regular</code>, <code>dev</code>, <code>peer</code>, <code>optional</code></p></li>
    /// <li>
    /// <p>maven: <code>optional</code>, <code>parent</code>, <code>compile</code>, <code>runtime</code>, <code>test</code>, <code>system</code>, <code>provided</code>.</p><note>
    /// <p>Note that <code>parent</code> is not a regular Maven dependency type; instead this is extracted from the <code><parent></parent></code> element if one is defined in the package version's POM file.</p>
    /// </note></li>
    /// <li>
    /// <p>nuget: The <code>dependencyType</code> field is never set for NuGet packages.</p></li>
    /// <li>
    /// <p>pypi: <code>Requires-Dist</code></p></li>
    /// </ul>
    pub fn dependency_type(&self) -> ::std::option::Option<&str> {
        self.dependency_type.as_deref()
    }
    /// <p>The required version, or version range, of the package that this package depends on. The version format is specific to the package type. For example, the following are possible valid required versions: <code>1.2.3</code>, <code>^2.3.4</code>, or <code>4.x</code>.</p>
    pub fn version_requirement(&self) -> ::std::option::Option<&str> {
        self.version_requirement.as_deref()
    }
}
impl PackageDependency {
    /// Creates a new builder-style object to manufacture [`PackageDependency`](crate::types::PackageDependency).
    pub fn builder() -> crate::types::builders::PackageDependencyBuilder {
        crate::types::builders::PackageDependencyBuilder::default()
    }
}

/// A builder for [`PackageDependency`](crate::types::PackageDependency).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PackageDependencyBuilder {
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
    pub(crate) package: ::std::option::Option<::std::string::String>,
    pub(crate) dependency_type: ::std::option::Option<::std::string::String>,
    pub(crate) version_requirement: ::std::option::Option<::std::string::String>,
}
impl PackageDependencyBuilder {
    /// <p>The namespace of the package that this package depends on. The package component that specifies its namespace depends on its type. For example:</p>
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
    /// <p>The namespace of the package that this package depends on. The package component that specifies its namespace depends on its type. For example:</p>
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
    /// <p>The namespace of the package that this package depends on. The package component that specifies its namespace depends on its type. For example:</p>
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
    /// <p>The name of the package that this package depends on.</p>
    pub fn package(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.package = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the package that this package depends on.</p>
    pub fn set_package(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.package = input;
        self
    }
    /// <p>The name of the package that this package depends on.</p>
    pub fn get_package(&self) -> &::std::option::Option<::std::string::String> {
        &self.package
    }
    /// <p>The type of a package dependency. The possible values depend on the package type.</p>
    /// <ul>
    /// <li>
    /// <p>npm: <code>regular</code>, <code>dev</code>, <code>peer</code>, <code>optional</code></p></li>
    /// <li>
    /// <p>maven: <code>optional</code>, <code>parent</code>, <code>compile</code>, <code>runtime</code>, <code>test</code>, <code>system</code>, <code>provided</code>.</p><note>
    /// <p>Note that <code>parent</code> is not a regular Maven dependency type; instead this is extracted from the <code><parent></parent></code> element if one is defined in the package version's POM file.</p>
    /// </note></li>
    /// <li>
    /// <p>nuget: The <code>dependencyType</code> field is never set for NuGet packages.</p></li>
    /// <li>
    /// <p>pypi: <code>Requires-Dist</code></p></li>
    /// </ul>
    pub fn dependency_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dependency_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of a package dependency. The possible values depend on the package type.</p>
    /// <ul>
    /// <li>
    /// <p>npm: <code>regular</code>, <code>dev</code>, <code>peer</code>, <code>optional</code></p></li>
    /// <li>
    /// <p>maven: <code>optional</code>, <code>parent</code>, <code>compile</code>, <code>runtime</code>, <code>test</code>, <code>system</code>, <code>provided</code>.</p><note>
    /// <p>Note that <code>parent</code> is not a regular Maven dependency type; instead this is extracted from the <code><parent></parent></code> element if one is defined in the package version's POM file.</p>
    /// </note></li>
    /// <li>
    /// <p>nuget: The <code>dependencyType</code> field is never set for NuGet packages.</p></li>
    /// <li>
    /// <p>pypi: <code>Requires-Dist</code></p></li>
    /// </ul>
    pub fn set_dependency_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dependency_type = input;
        self
    }
    /// <p>The type of a package dependency. The possible values depend on the package type.</p>
    /// <ul>
    /// <li>
    /// <p>npm: <code>regular</code>, <code>dev</code>, <code>peer</code>, <code>optional</code></p></li>
    /// <li>
    /// <p>maven: <code>optional</code>, <code>parent</code>, <code>compile</code>, <code>runtime</code>, <code>test</code>, <code>system</code>, <code>provided</code>.</p><note>
    /// <p>Note that <code>parent</code> is not a regular Maven dependency type; instead this is extracted from the <code><parent></parent></code> element if one is defined in the package version's POM file.</p>
    /// </note></li>
    /// <li>
    /// <p>nuget: The <code>dependencyType</code> field is never set for NuGet packages.</p></li>
    /// <li>
    /// <p>pypi: <code>Requires-Dist</code></p></li>
    /// </ul>
    pub fn get_dependency_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.dependency_type
    }
    /// <p>The required version, or version range, of the package that this package depends on. The version format is specific to the package type. For example, the following are possible valid required versions: <code>1.2.3</code>, <code>^2.3.4</code>, or <code>4.x</code>.</p>
    pub fn version_requirement(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_requirement = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The required version, or version range, of the package that this package depends on. The version format is specific to the package type. For example, the following are possible valid required versions: <code>1.2.3</code>, <code>^2.3.4</code>, or <code>4.x</code>.</p>
    pub fn set_version_requirement(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_requirement = input;
        self
    }
    /// <p>The required version, or version range, of the package that this package depends on. The version format is specific to the package type. For example, the following are possible valid required versions: <code>1.2.3</code>, <code>^2.3.4</code>, or <code>4.x</code>.</p>
    pub fn get_version_requirement(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_requirement
    }
    /// Consumes the builder and constructs a [`PackageDependency`](crate::types::PackageDependency).
    pub fn build(self) -> crate::types::PackageDependency {
        crate::types::PackageDependency {
            namespace: self.namespace,
            package: self.package,
            dependency_type: self.dependency_type,
            version_requirement: self.version_requirement,
        }
    }
}
