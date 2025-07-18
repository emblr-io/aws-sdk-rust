// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies whether the model container is in Amazon ECR or a private Docker registry accessible from your Amazon Virtual Private Cloud (VPC).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImageConfig {
    /// <p>Set this to one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>Platform</code> - The model image is hosted in Amazon ECR.</p></li>
    /// <li>
    /// <p><code>Vpc</code> - The model image is hosted in a private Docker registry in your VPC.</p></li>
    /// </ul>
    pub repository_access_mode: ::std::option::Option<crate::types::RepositoryAccessMode>,
    /// <p>(Optional) Specifies an authentication configuration for the private docker registry where your model image is hosted. Specify a value for this property only if you specified <code>Vpc</code> as the value for the <code>RepositoryAccessMode</code> field, and the private Docker registry where the model image is hosted requires authentication.</p>
    pub repository_auth_config: ::std::option::Option<crate::types::RepositoryAuthConfig>,
}
impl ImageConfig {
    /// <p>Set this to one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>Platform</code> - The model image is hosted in Amazon ECR.</p></li>
    /// <li>
    /// <p><code>Vpc</code> - The model image is hosted in a private Docker registry in your VPC.</p></li>
    /// </ul>
    pub fn repository_access_mode(&self) -> ::std::option::Option<&crate::types::RepositoryAccessMode> {
        self.repository_access_mode.as_ref()
    }
    /// <p>(Optional) Specifies an authentication configuration for the private docker registry where your model image is hosted. Specify a value for this property only if you specified <code>Vpc</code> as the value for the <code>RepositoryAccessMode</code> field, and the private Docker registry where the model image is hosted requires authentication.</p>
    pub fn repository_auth_config(&self) -> ::std::option::Option<&crate::types::RepositoryAuthConfig> {
        self.repository_auth_config.as_ref()
    }
}
impl ImageConfig {
    /// Creates a new builder-style object to manufacture [`ImageConfig`](crate::types::ImageConfig).
    pub fn builder() -> crate::types::builders::ImageConfigBuilder {
        crate::types::builders::ImageConfigBuilder::default()
    }
}

/// A builder for [`ImageConfig`](crate::types::ImageConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImageConfigBuilder {
    pub(crate) repository_access_mode: ::std::option::Option<crate::types::RepositoryAccessMode>,
    pub(crate) repository_auth_config: ::std::option::Option<crate::types::RepositoryAuthConfig>,
}
impl ImageConfigBuilder {
    /// <p>Set this to one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>Platform</code> - The model image is hosted in Amazon ECR.</p></li>
    /// <li>
    /// <p><code>Vpc</code> - The model image is hosted in a private Docker registry in your VPC.</p></li>
    /// </ul>
    /// This field is required.
    pub fn repository_access_mode(mut self, input: crate::types::RepositoryAccessMode) -> Self {
        self.repository_access_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set this to one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>Platform</code> - The model image is hosted in Amazon ECR.</p></li>
    /// <li>
    /// <p><code>Vpc</code> - The model image is hosted in a private Docker registry in your VPC.</p></li>
    /// </ul>
    pub fn set_repository_access_mode(mut self, input: ::std::option::Option<crate::types::RepositoryAccessMode>) -> Self {
        self.repository_access_mode = input;
        self
    }
    /// <p>Set this to one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>Platform</code> - The model image is hosted in Amazon ECR.</p></li>
    /// <li>
    /// <p><code>Vpc</code> - The model image is hosted in a private Docker registry in your VPC.</p></li>
    /// </ul>
    pub fn get_repository_access_mode(&self) -> &::std::option::Option<crate::types::RepositoryAccessMode> {
        &self.repository_access_mode
    }
    /// <p>(Optional) Specifies an authentication configuration for the private docker registry where your model image is hosted. Specify a value for this property only if you specified <code>Vpc</code> as the value for the <code>RepositoryAccessMode</code> field, and the private Docker registry where the model image is hosted requires authentication.</p>
    pub fn repository_auth_config(mut self, input: crate::types::RepositoryAuthConfig) -> Self {
        self.repository_auth_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>(Optional) Specifies an authentication configuration for the private docker registry where your model image is hosted. Specify a value for this property only if you specified <code>Vpc</code> as the value for the <code>RepositoryAccessMode</code> field, and the private Docker registry where the model image is hosted requires authentication.</p>
    pub fn set_repository_auth_config(mut self, input: ::std::option::Option<crate::types::RepositoryAuthConfig>) -> Self {
        self.repository_auth_config = input;
        self
    }
    /// <p>(Optional) Specifies an authentication configuration for the private docker registry where your model image is hosted. Specify a value for this property only if you specified <code>Vpc</code> as the value for the <code>RepositoryAccessMode</code> field, and the private Docker registry where the model image is hosted requires authentication.</p>
    pub fn get_repository_auth_config(&self) -> &::std::option::Option<crate::types::RepositoryAuthConfig> {
        &self.repository_auth_config
    }
    /// Consumes the builder and constructs a [`ImageConfig`](crate::types::ImageConfig).
    pub fn build(self) -> crate::types::ImageConfig {
        crate::types::ImageConfig {
            repository_access_mode: self.repository_access_mode,
            repository_auth_config: self.repository_auth_config,
        }
    }
}
