// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateImagePipelineInput {
    /// <p>The Amazon Resource Name (ARN) of the image pipeline that you want to update.</p>
    pub image_pipeline_arn: ::std::option::Option<::std::string::String>,
    /// <p>The description of the image pipeline.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the image recipe that will be used to configure images updated by this image pipeline.</p>
    pub image_recipe_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the container pipeline to update.</p>
    pub container_recipe_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration that Image Builder uses to build images that this image pipeline has updated.</p>
    pub infrastructure_configuration_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration that Image Builder uses to configure and distribute images that this image pipeline has updated.</p>
    pub distribution_configuration_arn: ::std::option::Option<::std::string::String>,
    /// <p>The image test configuration of the image pipeline.</p>
    pub image_tests_configuration: ::std::option::Option<crate::types::ImageTestsConfiguration>,
    /// <p>Collects additional information about the image being created, including the operating system (OS) version and package list. This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.</p>
    pub enhanced_image_metadata_enabled: ::std::option::Option<bool>,
    /// <p>The schedule of the image pipeline.</p>
    pub schedule: ::std::option::Option<crate::types::Schedule>,
    /// <p>The status of the image pipeline.</p>
    pub status: ::std::option::Option<crate::types::PipelineStatus>,
    /// <p>Unique, case-sensitive identifier you provide to ensure idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensuring idempotency</a> in the <i>Amazon EC2 API Reference</i>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Contains settings for vulnerability scans.</p>
    pub image_scanning_configuration: ::std::option::Option<crate::types::ImageScanningConfiguration>,
    /// <p>Contains the workflows to run for the pipeline.</p>
    pub workflows: ::std::option::Option<::std::vec::Vec<crate::types::WorkflowConfiguration>>,
    /// <p>The name or Amazon Resource Name (ARN) for the IAM role you create that grants Image Builder access to perform workflow actions.</p>
    pub execution_role: ::std::option::Option<::std::string::String>,
}
impl UpdateImagePipelineInput {
    /// <p>The Amazon Resource Name (ARN) of the image pipeline that you want to update.</p>
    pub fn image_pipeline_arn(&self) -> ::std::option::Option<&str> {
        self.image_pipeline_arn.as_deref()
    }
    /// <p>The description of the image pipeline.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the image recipe that will be used to configure images updated by this image pipeline.</p>
    pub fn image_recipe_arn(&self) -> ::std::option::Option<&str> {
        self.image_recipe_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the container pipeline to update.</p>
    pub fn container_recipe_arn(&self) -> ::std::option::Option<&str> {
        self.container_recipe_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration that Image Builder uses to build images that this image pipeline has updated.</p>
    pub fn infrastructure_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.infrastructure_configuration_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration that Image Builder uses to configure and distribute images that this image pipeline has updated.</p>
    pub fn distribution_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.distribution_configuration_arn.as_deref()
    }
    /// <p>The image test configuration of the image pipeline.</p>
    pub fn image_tests_configuration(&self) -> ::std::option::Option<&crate::types::ImageTestsConfiguration> {
        self.image_tests_configuration.as_ref()
    }
    /// <p>Collects additional information about the image being created, including the operating system (OS) version and package list. This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.</p>
    pub fn enhanced_image_metadata_enabled(&self) -> ::std::option::Option<bool> {
        self.enhanced_image_metadata_enabled
    }
    /// <p>The schedule of the image pipeline.</p>
    pub fn schedule(&self) -> ::std::option::Option<&crate::types::Schedule> {
        self.schedule.as_ref()
    }
    /// <p>The status of the image pipeline.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::PipelineStatus> {
        self.status.as_ref()
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensuring idempotency</a> in the <i>Amazon EC2 API Reference</i>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Contains settings for vulnerability scans.</p>
    pub fn image_scanning_configuration(&self) -> ::std::option::Option<&crate::types::ImageScanningConfiguration> {
        self.image_scanning_configuration.as_ref()
    }
    /// <p>Contains the workflows to run for the pipeline.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.workflows.is_none()`.
    pub fn workflows(&self) -> &[crate::types::WorkflowConfiguration] {
        self.workflows.as_deref().unwrap_or_default()
    }
    /// <p>The name or Amazon Resource Name (ARN) for the IAM role you create that grants Image Builder access to perform workflow actions.</p>
    pub fn execution_role(&self) -> ::std::option::Option<&str> {
        self.execution_role.as_deref()
    }
}
impl UpdateImagePipelineInput {
    /// Creates a new builder-style object to manufacture [`UpdateImagePipelineInput`](crate::operation::update_image_pipeline::UpdateImagePipelineInput).
    pub fn builder() -> crate::operation::update_image_pipeline::builders::UpdateImagePipelineInputBuilder {
        crate::operation::update_image_pipeline::builders::UpdateImagePipelineInputBuilder::default()
    }
}

/// A builder for [`UpdateImagePipelineInput`](crate::operation::update_image_pipeline::UpdateImagePipelineInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateImagePipelineInputBuilder {
    pub(crate) image_pipeline_arn: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) image_recipe_arn: ::std::option::Option<::std::string::String>,
    pub(crate) container_recipe_arn: ::std::option::Option<::std::string::String>,
    pub(crate) infrastructure_configuration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) distribution_configuration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) image_tests_configuration: ::std::option::Option<crate::types::ImageTestsConfiguration>,
    pub(crate) enhanced_image_metadata_enabled: ::std::option::Option<bool>,
    pub(crate) schedule: ::std::option::Option<crate::types::Schedule>,
    pub(crate) status: ::std::option::Option<crate::types::PipelineStatus>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) image_scanning_configuration: ::std::option::Option<crate::types::ImageScanningConfiguration>,
    pub(crate) workflows: ::std::option::Option<::std::vec::Vec<crate::types::WorkflowConfiguration>>,
    pub(crate) execution_role: ::std::option::Option<::std::string::String>,
}
impl UpdateImagePipelineInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the image pipeline that you want to update.</p>
    /// This field is required.
    pub fn image_pipeline_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_pipeline_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the image pipeline that you want to update.</p>
    pub fn set_image_pipeline_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_pipeline_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the image pipeline that you want to update.</p>
    pub fn get_image_pipeline_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_pipeline_arn
    }
    /// <p>The description of the image pipeline.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the image pipeline.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the image pipeline.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The Amazon Resource Name (ARN) of the image recipe that will be used to configure images updated by this image pipeline.</p>
    pub fn image_recipe_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_recipe_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the image recipe that will be used to configure images updated by this image pipeline.</p>
    pub fn set_image_recipe_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_recipe_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the image recipe that will be used to configure images updated by this image pipeline.</p>
    pub fn get_image_recipe_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_recipe_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the container pipeline to update.</p>
    pub fn container_recipe_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.container_recipe_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the container pipeline to update.</p>
    pub fn set_container_recipe_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.container_recipe_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the container pipeline to update.</p>
    pub fn get_container_recipe_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.container_recipe_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration that Image Builder uses to build images that this image pipeline has updated.</p>
    /// This field is required.
    pub fn infrastructure_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.infrastructure_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration that Image Builder uses to build images that this image pipeline has updated.</p>
    pub fn set_infrastructure_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.infrastructure_configuration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration that Image Builder uses to build images that this image pipeline has updated.</p>
    pub fn get_infrastructure_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.infrastructure_configuration_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration that Image Builder uses to configure and distribute images that this image pipeline has updated.</p>
    pub fn distribution_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.distribution_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration that Image Builder uses to configure and distribute images that this image pipeline has updated.</p>
    pub fn set_distribution_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.distribution_configuration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration that Image Builder uses to configure and distribute images that this image pipeline has updated.</p>
    pub fn get_distribution_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.distribution_configuration_arn
    }
    /// <p>The image test configuration of the image pipeline.</p>
    pub fn image_tests_configuration(mut self, input: crate::types::ImageTestsConfiguration) -> Self {
        self.image_tests_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The image test configuration of the image pipeline.</p>
    pub fn set_image_tests_configuration(mut self, input: ::std::option::Option<crate::types::ImageTestsConfiguration>) -> Self {
        self.image_tests_configuration = input;
        self
    }
    /// <p>The image test configuration of the image pipeline.</p>
    pub fn get_image_tests_configuration(&self) -> &::std::option::Option<crate::types::ImageTestsConfiguration> {
        &self.image_tests_configuration
    }
    /// <p>Collects additional information about the image being created, including the operating system (OS) version and package list. This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.</p>
    pub fn enhanced_image_metadata_enabled(mut self, input: bool) -> Self {
        self.enhanced_image_metadata_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Collects additional information about the image being created, including the operating system (OS) version and package list. This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.</p>
    pub fn set_enhanced_image_metadata_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enhanced_image_metadata_enabled = input;
        self
    }
    /// <p>Collects additional information about the image being created, including the operating system (OS) version and package list. This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.</p>
    pub fn get_enhanced_image_metadata_enabled(&self) -> &::std::option::Option<bool> {
        &self.enhanced_image_metadata_enabled
    }
    /// <p>The schedule of the image pipeline.</p>
    pub fn schedule(mut self, input: crate::types::Schedule) -> Self {
        self.schedule = ::std::option::Option::Some(input);
        self
    }
    /// <p>The schedule of the image pipeline.</p>
    pub fn set_schedule(mut self, input: ::std::option::Option<crate::types::Schedule>) -> Self {
        self.schedule = input;
        self
    }
    /// <p>The schedule of the image pipeline.</p>
    pub fn get_schedule(&self) -> &::std::option::Option<crate::types::Schedule> {
        &self.schedule
    }
    /// <p>The status of the image pipeline.</p>
    pub fn status(mut self, input: crate::types::PipelineStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the image pipeline.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::PipelineStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the image pipeline.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::PipelineStatus> {
        &self.status
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
    /// <p>Contains settings for vulnerability scans.</p>
    pub fn image_scanning_configuration(mut self, input: crate::types::ImageScanningConfiguration) -> Self {
        self.image_scanning_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains settings for vulnerability scans.</p>
    pub fn set_image_scanning_configuration(mut self, input: ::std::option::Option<crate::types::ImageScanningConfiguration>) -> Self {
        self.image_scanning_configuration = input;
        self
    }
    /// <p>Contains settings for vulnerability scans.</p>
    pub fn get_image_scanning_configuration(&self) -> &::std::option::Option<crate::types::ImageScanningConfiguration> {
        &self.image_scanning_configuration
    }
    /// Appends an item to `workflows`.
    ///
    /// To override the contents of this collection use [`set_workflows`](Self::set_workflows).
    ///
    /// <p>Contains the workflows to run for the pipeline.</p>
    pub fn workflows(mut self, input: crate::types::WorkflowConfiguration) -> Self {
        let mut v = self.workflows.unwrap_or_default();
        v.push(input);
        self.workflows = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains the workflows to run for the pipeline.</p>
    pub fn set_workflows(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::WorkflowConfiguration>>) -> Self {
        self.workflows = input;
        self
    }
    /// <p>Contains the workflows to run for the pipeline.</p>
    pub fn get_workflows(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::WorkflowConfiguration>> {
        &self.workflows
    }
    /// <p>The name or Amazon Resource Name (ARN) for the IAM role you create that grants Image Builder access to perform workflow actions.</p>
    pub fn execution_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) for the IAM role you create that grants Image Builder access to perform workflow actions.</p>
    pub fn set_execution_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_role = input;
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) for the IAM role you create that grants Image Builder access to perform workflow actions.</p>
    pub fn get_execution_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_role
    }
    /// Consumes the builder and constructs a [`UpdateImagePipelineInput`](crate::operation::update_image_pipeline::UpdateImagePipelineInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_image_pipeline::UpdateImagePipelineInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_image_pipeline::UpdateImagePipelineInput {
            image_pipeline_arn: self.image_pipeline_arn,
            description: self.description,
            image_recipe_arn: self.image_recipe_arn,
            container_recipe_arn: self.container_recipe_arn,
            infrastructure_configuration_arn: self.infrastructure_configuration_arn,
            distribution_configuration_arn: self.distribution_configuration_arn,
            image_tests_configuration: self.image_tests_configuration,
            enhanced_image_metadata_enabled: self.enhanced_image_metadata_enabled,
            schedule: self.schedule,
            status: self.status,
            client_token: self.client_token,
            image_scanning_configuration: self.image_scanning_configuration,
            workflows: self.workflows,
            execution_role: self.execution_role,
        })
    }
}
