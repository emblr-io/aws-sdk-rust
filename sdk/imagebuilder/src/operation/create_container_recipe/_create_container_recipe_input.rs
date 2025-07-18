// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateContainerRecipeInput {
    /// <p>The type of container to create.</p>
    pub container_type: ::std::option::Option<crate::types::ContainerType>,
    /// <p>The name of the container recipe.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the container recipe.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The semantic version of the container recipe. This version follows the semantic version syntax.</p><note>
    /// <p>The semantic version has four nodes: <major>
    /// .
    /// <minor>
    /// .
    /// <patch>
    /// /
    /// <build>
    /// . You can assign values for the first three, and can filter on all of them.
    /// </build>
    /// </patch>
    /// </minor>
    /// </major></p>
    /// <p><b>Assignment:</b> For the first three nodes you can assign any positive integer value, including zero, with an upper limit of 2^30-1, or 1073741823 for each node. Image Builder automatically assigns the build number to the fourth node.</p>
    /// <p><b>Patterns:</b> You can use any numeric pattern that adheres to the assignment requirements for the nodes that you can assign. For example, you might choose a software version pattern, such as 1.0.0, or a date, such as 2021.01.01.</p>
    /// </note>
    pub semantic_version: ::std::option::Option<::std::string::String>,
    /// <p>Components for build and test that are included in the container recipe. Recipes require a minimum of one build component, and can have a maximum of 20 build and test components in any combination.</p>
    pub components: ::std::option::Option<::std::vec::Vec<crate::types::ComponentConfiguration>>,
    /// <p>A group of options that can be used to configure an instance for building and testing container images.</p>
    pub instance_configuration: ::std::option::Option<crate::types::InstanceConfiguration>,
    /// <p>The Dockerfile template used to build your image as an inline data blob.</p>
    pub dockerfile_template_data: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon S3 URI for the Dockerfile that will be used to build your container image.</p>
    pub dockerfile_template_uri: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the operating system platform when you use a custom base image.</p>
    pub platform_override: ::std::option::Option<crate::types::Platform>,
    /// <p>Specifies the operating system version for the base image.</p>
    pub image_os_version_override: ::std::option::Option<::std::string::String>,
    /// <p>The base image for the container recipe.</p>
    pub parent_image: ::std::option::Option<::std::string::String>,
    /// <p>Tags that are attached to the container recipe.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The working directory for use during build and test workflows.</p>
    pub working_directory: ::std::option::Option<::std::string::String>,
    /// <p>The destination repository for the container image.</p>
    pub target_repository: ::std::option::Option<crate::types::TargetContainerRepository>,
    /// <p>Identifies which KMS key is used to encrypt the Dockerfile template.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>Unique, case-sensitive identifier you provide to ensure idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensuring idempotency</a> in the <i>Amazon EC2 API Reference</i>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreateContainerRecipeInput {
    /// <p>The type of container to create.</p>
    pub fn container_type(&self) -> ::std::option::Option<&crate::types::ContainerType> {
        self.container_type.as_ref()
    }
    /// <p>The name of the container recipe.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the container recipe.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The semantic version of the container recipe. This version follows the semantic version syntax.</p><note>
    /// <p>The semantic version has four nodes: <major>
    /// .
    /// <minor>
    /// .
    /// <patch>
    /// /
    /// <build>
    /// . You can assign values for the first three, and can filter on all of them.
    /// </build>
    /// </patch>
    /// </minor>
    /// </major></p>
    /// <p><b>Assignment:</b> For the first three nodes you can assign any positive integer value, including zero, with an upper limit of 2^30-1, or 1073741823 for each node. Image Builder automatically assigns the build number to the fourth node.</p>
    /// <p><b>Patterns:</b> You can use any numeric pattern that adheres to the assignment requirements for the nodes that you can assign. For example, you might choose a software version pattern, such as 1.0.0, or a date, such as 2021.01.01.</p>
    /// </note>
    pub fn semantic_version(&self) -> ::std::option::Option<&str> {
        self.semantic_version.as_deref()
    }
    /// <p>Components for build and test that are included in the container recipe. Recipes require a minimum of one build component, and can have a maximum of 20 build and test components in any combination.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.components.is_none()`.
    pub fn components(&self) -> &[crate::types::ComponentConfiguration] {
        self.components.as_deref().unwrap_or_default()
    }
    /// <p>A group of options that can be used to configure an instance for building and testing container images.</p>
    pub fn instance_configuration(&self) -> ::std::option::Option<&crate::types::InstanceConfiguration> {
        self.instance_configuration.as_ref()
    }
    /// <p>The Dockerfile template used to build your image as an inline data blob.</p>
    pub fn dockerfile_template_data(&self) -> ::std::option::Option<&str> {
        self.dockerfile_template_data.as_deref()
    }
    /// <p>The Amazon S3 URI for the Dockerfile that will be used to build your container image.</p>
    pub fn dockerfile_template_uri(&self) -> ::std::option::Option<&str> {
        self.dockerfile_template_uri.as_deref()
    }
    /// <p>Specifies the operating system platform when you use a custom base image.</p>
    pub fn platform_override(&self) -> ::std::option::Option<&crate::types::Platform> {
        self.platform_override.as_ref()
    }
    /// <p>Specifies the operating system version for the base image.</p>
    pub fn image_os_version_override(&self) -> ::std::option::Option<&str> {
        self.image_os_version_override.as_deref()
    }
    /// <p>The base image for the container recipe.</p>
    pub fn parent_image(&self) -> ::std::option::Option<&str> {
        self.parent_image.as_deref()
    }
    /// <p>Tags that are attached to the container recipe.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The working directory for use during build and test workflows.</p>
    pub fn working_directory(&self) -> ::std::option::Option<&str> {
        self.working_directory.as_deref()
    }
    /// <p>The destination repository for the container image.</p>
    pub fn target_repository(&self) -> ::std::option::Option<&crate::types::TargetContainerRepository> {
        self.target_repository.as_ref()
    }
    /// <p>Identifies which KMS key is used to encrypt the Dockerfile template.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensuring idempotency</a> in the <i>Amazon EC2 API Reference</i>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl CreateContainerRecipeInput {
    /// Creates a new builder-style object to manufacture [`CreateContainerRecipeInput`](crate::operation::create_container_recipe::CreateContainerRecipeInput).
    pub fn builder() -> crate::operation::create_container_recipe::builders::CreateContainerRecipeInputBuilder {
        crate::operation::create_container_recipe::builders::CreateContainerRecipeInputBuilder::default()
    }
}

/// A builder for [`CreateContainerRecipeInput`](crate::operation::create_container_recipe::CreateContainerRecipeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateContainerRecipeInputBuilder {
    pub(crate) container_type: ::std::option::Option<crate::types::ContainerType>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) semantic_version: ::std::option::Option<::std::string::String>,
    pub(crate) components: ::std::option::Option<::std::vec::Vec<crate::types::ComponentConfiguration>>,
    pub(crate) instance_configuration: ::std::option::Option<crate::types::InstanceConfiguration>,
    pub(crate) dockerfile_template_data: ::std::option::Option<::std::string::String>,
    pub(crate) dockerfile_template_uri: ::std::option::Option<::std::string::String>,
    pub(crate) platform_override: ::std::option::Option<crate::types::Platform>,
    pub(crate) image_os_version_override: ::std::option::Option<::std::string::String>,
    pub(crate) parent_image: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) working_directory: ::std::option::Option<::std::string::String>,
    pub(crate) target_repository: ::std::option::Option<crate::types::TargetContainerRepository>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreateContainerRecipeInputBuilder {
    /// <p>The type of container to create.</p>
    /// This field is required.
    pub fn container_type(mut self, input: crate::types::ContainerType) -> Self {
        self.container_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of container to create.</p>
    pub fn set_container_type(mut self, input: ::std::option::Option<crate::types::ContainerType>) -> Self {
        self.container_type = input;
        self
    }
    /// <p>The type of container to create.</p>
    pub fn get_container_type(&self) -> &::std::option::Option<crate::types::ContainerType> {
        &self.container_type
    }
    /// <p>The name of the container recipe.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the container recipe.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the container recipe.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the container recipe.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the container recipe.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the container recipe.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The semantic version of the container recipe. This version follows the semantic version syntax.</p><note>
    /// <p>The semantic version has four nodes: <major>
    /// .
    /// <minor>
    /// .
    /// <patch>
    /// /
    /// <build>
    /// . You can assign values for the first three, and can filter on all of them.
    /// </build>
    /// </patch>
    /// </minor>
    /// </major></p>
    /// <p><b>Assignment:</b> For the first three nodes you can assign any positive integer value, including zero, with an upper limit of 2^30-1, or 1073741823 for each node. Image Builder automatically assigns the build number to the fourth node.</p>
    /// <p><b>Patterns:</b> You can use any numeric pattern that adheres to the assignment requirements for the nodes that you can assign. For example, you might choose a software version pattern, such as 1.0.0, or a date, such as 2021.01.01.</p>
    /// </note>
    /// This field is required.
    pub fn semantic_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.semantic_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The semantic version of the container recipe. This version follows the semantic version syntax.</p><note>
    /// <p>The semantic version has four nodes: <major>
    /// .
    /// <minor>
    /// .
    /// <patch>
    /// /
    /// <build>
    /// . You can assign values for the first three, and can filter on all of them.
    /// </build>
    /// </patch>
    /// </minor>
    /// </major></p>
    /// <p><b>Assignment:</b> For the first three nodes you can assign any positive integer value, including zero, with an upper limit of 2^30-1, or 1073741823 for each node. Image Builder automatically assigns the build number to the fourth node.</p>
    /// <p><b>Patterns:</b> You can use any numeric pattern that adheres to the assignment requirements for the nodes that you can assign. For example, you might choose a software version pattern, such as 1.0.0, or a date, such as 2021.01.01.</p>
    /// </note>
    pub fn set_semantic_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.semantic_version = input;
        self
    }
    /// <p>The semantic version of the container recipe. This version follows the semantic version syntax.</p><note>
    /// <p>The semantic version has four nodes: <major>
    /// .
    /// <minor>
    /// .
    /// <patch>
    /// /
    /// <build>
    /// . You can assign values for the first three, and can filter on all of them.
    /// </build>
    /// </patch>
    /// </minor>
    /// </major></p>
    /// <p><b>Assignment:</b> For the first three nodes you can assign any positive integer value, including zero, with an upper limit of 2^30-1, or 1073741823 for each node. Image Builder automatically assigns the build number to the fourth node.</p>
    /// <p><b>Patterns:</b> You can use any numeric pattern that adheres to the assignment requirements for the nodes that you can assign. For example, you might choose a software version pattern, such as 1.0.0, or a date, such as 2021.01.01.</p>
    /// </note>
    pub fn get_semantic_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.semantic_version
    }
    /// Appends an item to `components`.
    ///
    /// To override the contents of this collection use [`set_components`](Self::set_components).
    ///
    /// <p>Components for build and test that are included in the container recipe. Recipes require a minimum of one build component, and can have a maximum of 20 build and test components in any combination.</p>
    pub fn components(mut self, input: crate::types::ComponentConfiguration) -> Self {
        let mut v = self.components.unwrap_or_default();
        v.push(input);
        self.components = ::std::option::Option::Some(v);
        self
    }
    /// <p>Components for build and test that are included in the container recipe. Recipes require a minimum of one build component, and can have a maximum of 20 build and test components in any combination.</p>
    pub fn set_components(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ComponentConfiguration>>) -> Self {
        self.components = input;
        self
    }
    /// <p>Components for build and test that are included in the container recipe. Recipes require a minimum of one build component, and can have a maximum of 20 build and test components in any combination.</p>
    pub fn get_components(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ComponentConfiguration>> {
        &self.components
    }
    /// <p>A group of options that can be used to configure an instance for building and testing container images.</p>
    pub fn instance_configuration(mut self, input: crate::types::InstanceConfiguration) -> Self {
        self.instance_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A group of options that can be used to configure an instance for building and testing container images.</p>
    pub fn set_instance_configuration(mut self, input: ::std::option::Option<crate::types::InstanceConfiguration>) -> Self {
        self.instance_configuration = input;
        self
    }
    /// <p>A group of options that can be used to configure an instance for building and testing container images.</p>
    pub fn get_instance_configuration(&self) -> &::std::option::Option<crate::types::InstanceConfiguration> {
        &self.instance_configuration
    }
    /// <p>The Dockerfile template used to build your image as an inline data blob.</p>
    pub fn dockerfile_template_data(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dockerfile_template_data = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Dockerfile template used to build your image as an inline data blob.</p>
    pub fn set_dockerfile_template_data(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dockerfile_template_data = input;
        self
    }
    /// <p>The Dockerfile template used to build your image as an inline data blob.</p>
    pub fn get_dockerfile_template_data(&self) -> &::std::option::Option<::std::string::String> {
        &self.dockerfile_template_data
    }
    /// <p>The Amazon S3 URI for the Dockerfile that will be used to build your container image.</p>
    pub fn dockerfile_template_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dockerfile_template_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 URI for the Dockerfile that will be used to build your container image.</p>
    pub fn set_dockerfile_template_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dockerfile_template_uri = input;
        self
    }
    /// <p>The Amazon S3 URI for the Dockerfile that will be used to build your container image.</p>
    pub fn get_dockerfile_template_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.dockerfile_template_uri
    }
    /// <p>Specifies the operating system platform when you use a custom base image.</p>
    pub fn platform_override(mut self, input: crate::types::Platform) -> Self {
        self.platform_override = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the operating system platform when you use a custom base image.</p>
    pub fn set_platform_override(mut self, input: ::std::option::Option<crate::types::Platform>) -> Self {
        self.platform_override = input;
        self
    }
    /// <p>Specifies the operating system platform when you use a custom base image.</p>
    pub fn get_platform_override(&self) -> &::std::option::Option<crate::types::Platform> {
        &self.platform_override
    }
    /// <p>Specifies the operating system version for the base image.</p>
    pub fn image_os_version_override(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_os_version_override = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the operating system version for the base image.</p>
    pub fn set_image_os_version_override(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_os_version_override = input;
        self
    }
    /// <p>Specifies the operating system version for the base image.</p>
    pub fn get_image_os_version_override(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_os_version_override
    }
    /// <p>The base image for the container recipe.</p>
    /// This field is required.
    pub fn parent_image(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_image = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The base image for the container recipe.</p>
    pub fn set_parent_image(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_image = input;
        self
    }
    /// <p>The base image for the container recipe.</p>
    pub fn get_parent_image(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_image
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags that are attached to the container recipe.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Tags that are attached to the container recipe.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags that are attached to the container recipe.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The working directory for use during build and test workflows.</p>
    pub fn working_directory(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.working_directory = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The working directory for use during build and test workflows.</p>
    pub fn set_working_directory(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.working_directory = input;
        self
    }
    /// <p>The working directory for use during build and test workflows.</p>
    pub fn get_working_directory(&self) -> &::std::option::Option<::std::string::String> {
        &self.working_directory
    }
    /// <p>The destination repository for the container image.</p>
    /// This field is required.
    pub fn target_repository(mut self, input: crate::types::TargetContainerRepository) -> Self {
        self.target_repository = ::std::option::Option::Some(input);
        self
    }
    /// <p>The destination repository for the container image.</p>
    pub fn set_target_repository(mut self, input: ::std::option::Option<crate::types::TargetContainerRepository>) -> Self {
        self.target_repository = input;
        self
    }
    /// <p>The destination repository for the container image.</p>
    pub fn get_target_repository(&self) -> &::std::option::Option<crate::types::TargetContainerRepository> {
        &self.target_repository
    }
    /// <p>Identifies which KMS key is used to encrypt the Dockerfile template.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifies which KMS key is used to encrypt the Dockerfile template.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>Identifies which KMS key is used to encrypt the Dockerfile template.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensuring idempotency</a> in the <i>Amazon EC2 API Reference</i>.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensuring idempotency</a> in the <i>Amazon EC2 API Reference</i>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensuring idempotency</a> in the <i>Amazon EC2 API Reference</i>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreateContainerRecipeInput`](crate::operation::create_container_recipe::CreateContainerRecipeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_container_recipe::CreateContainerRecipeInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_container_recipe::CreateContainerRecipeInput {
            container_type: self.container_type,
            name: self.name,
            description: self.description,
            semantic_version: self.semantic_version,
            components: self.components,
            instance_configuration: self.instance_configuration,
            dockerfile_template_data: self.dockerfile_template_data,
            dockerfile_template_uri: self.dockerfile_template_uri,
            platform_override: self.platform_override,
            image_os_version_override: self.image_os_version_override,
            parent_image: self.parent_image,
            tags: self.tags,
            working_directory: self.working_directory,
            target_repository: self.target_repository,
            kms_key_id: self.kms_key_id,
            client_token: self.client_token,
        })
    }
}
