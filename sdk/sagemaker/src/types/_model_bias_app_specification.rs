// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Docker container image configuration object for the model bias job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModelBiasAppSpecification {
    /// <p>The container image to be run by the model bias job.</p>
    pub image_uri: ::std::option::Option<::std::string::String>,
    /// <p>JSON formatted S3 file that defines bias parameters. For more information on this JSON configuration file, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-config-json-monitor-bias-parameters.html">Configure bias parameters</a>.</p>
    pub config_uri: ::std::option::Option<::std::string::String>,
    /// <p>Sets the environment variables in the Docker container.</p>
    pub environment: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ModelBiasAppSpecification {
    /// <p>The container image to be run by the model bias job.</p>
    pub fn image_uri(&self) -> ::std::option::Option<&str> {
        self.image_uri.as_deref()
    }
    /// <p>JSON formatted S3 file that defines bias parameters. For more information on this JSON configuration file, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-config-json-monitor-bias-parameters.html">Configure bias parameters</a>.</p>
    pub fn config_uri(&self) -> ::std::option::Option<&str> {
        self.config_uri.as_deref()
    }
    /// <p>Sets the environment variables in the Docker container.</p>
    pub fn environment(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.environment.as_ref()
    }
}
impl ModelBiasAppSpecification {
    /// Creates a new builder-style object to manufacture [`ModelBiasAppSpecification`](crate::types::ModelBiasAppSpecification).
    pub fn builder() -> crate::types::builders::ModelBiasAppSpecificationBuilder {
        crate::types::builders::ModelBiasAppSpecificationBuilder::default()
    }
}

/// A builder for [`ModelBiasAppSpecification`](crate::types::ModelBiasAppSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModelBiasAppSpecificationBuilder {
    pub(crate) image_uri: ::std::option::Option<::std::string::String>,
    pub(crate) config_uri: ::std::option::Option<::std::string::String>,
    pub(crate) environment: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ModelBiasAppSpecificationBuilder {
    /// <p>The container image to be run by the model bias job.</p>
    /// This field is required.
    pub fn image_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The container image to be run by the model bias job.</p>
    pub fn set_image_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_uri = input;
        self
    }
    /// <p>The container image to be run by the model bias job.</p>
    pub fn get_image_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_uri
    }
    /// <p>JSON formatted S3 file that defines bias parameters. For more information on this JSON configuration file, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-config-json-monitor-bias-parameters.html">Configure bias parameters</a>.</p>
    /// This field is required.
    pub fn config_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.config_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>JSON formatted S3 file that defines bias parameters. For more information on this JSON configuration file, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-config-json-monitor-bias-parameters.html">Configure bias parameters</a>.</p>
    pub fn set_config_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.config_uri = input;
        self
    }
    /// <p>JSON formatted S3 file that defines bias parameters. For more information on this JSON configuration file, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-config-json-monitor-bias-parameters.html">Configure bias parameters</a>.</p>
    pub fn get_config_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.config_uri
    }
    /// Adds a key-value pair to `environment`.
    ///
    /// To override the contents of this collection use [`set_environment`](Self::set_environment).
    ///
    /// <p>Sets the environment variables in the Docker container.</p>
    pub fn environment(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.environment.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.environment = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Sets the environment variables in the Docker container.</p>
    pub fn set_environment(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.environment = input;
        self
    }
    /// <p>Sets the environment variables in the Docker container.</p>
    pub fn get_environment(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.environment
    }
    /// Consumes the builder and constructs a [`ModelBiasAppSpecification`](crate::types::ModelBiasAppSpecification).
    pub fn build(self) -> crate::types::ModelBiasAppSpecification {
        crate::types::ModelBiasAppSpecification {
            image_uri: self.image_uri,
            config_uri: self.config_uri,
            environment: self.environment,
        }
    }
}
