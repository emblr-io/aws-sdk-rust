// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details of an image pipeline.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImagePipeline {
    /// <p>The Amazon Resource Name (ARN) of the image pipeline.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the image pipeline.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the image pipeline.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The platform of the image pipeline.</p>
    pub platform: ::std::option::Option<crate::types::Platform>,
    /// <p>Collects additional information about the image being created, including the operating system (OS) version and package list. This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.</p>
    pub enhanced_image_metadata_enabled: ::std::option::Option<bool>,
    /// <p>The Amazon Resource Name (ARN) of the image recipe associated with this image pipeline.</p>
    pub image_recipe_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.</p>
    pub container_recipe_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.</p>
    pub infrastructure_configuration_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration associated with this image pipeline.</p>
    pub distribution_configuration_arn: ::std::option::Option<::std::string::String>,
    /// <p>The image tests configuration of the image pipeline.</p>
    pub image_tests_configuration: ::std::option::Option<crate::types::ImageTestsConfiguration>,
    /// <p>The schedule of the image pipeline.</p>
    pub schedule: ::std::option::Option<crate::types::Schedule>,
    /// <p>The status of the image pipeline.</p>
    pub status: ::std::option::Option<crate::types::PipelineStatus>,
    /// <p>The date on which this image pipeline was created.</p>
    pub date_created: ::std::option::Option<::std::string::String>,
    /// <p>The date on which this image pipeline was last updated.</p>
    pub date_updated: ::std::option::Option<::std::string::String>,
    /// <p>This is no longer supported, and does not return a value.</p>
    pub date_last_run: ::std::option::Option<::std::string::String>,
    /// <p>The next date when the pipeline is scheduled to run.</p>
    pub date_next_run: ::std::option::Option<::std::string::String>,
    /// <p>The tags of this image pipeline.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Contains settings for vulnerability scans.</p>
    pub image_scanning_configuration: ::std::option::Option<crate::types::ImageScanningConfiguration>,
    /// <p>The name or Amazon Resource Name (ARN) for the IAM role you create that grants Image Builder access to perform workflow actions.</p>
    pub execution_role: ::std::option::Option<::std::string::String>,
    /// <p>Contains the workflows that run for the image pipeline.</p>
    pub workflows: ::std::option::Option<::std::vec::Vec<crate::types::WorkflowConfiguration>>,
}
impl ImagePipeline {
    /// <p>The Amazon Resource Name (ARN) of the image pipeline.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the image pipeline.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the image pipeline.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The platform of the image pipeline.</p>
    pub fn platform(&self) -> ::std::option::Option<&crate::types::Platform> {
        self.platform.as_ref()
    }
    /// <p>Collects additional information about the image being created, including the operating system (OS) version and package list. This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.</p>
    pub fn enhanced_image_metadata_enabled(&self) -> ::std::option::Option<bool> {
        self.enhanced_image_metadata_enabled
    }
    /// <p>The Amazon Resource Name (ARN) of the image recipe associated with this image pipeline.</p>
    pub fn image_recipe_arn(&self) -> ::std::option::Option<&str> {
        self.image_recipe_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.</p>
    pub fn container_recipe_arn(&self) -> ::std::option::Option<&str> {
        self.container_recipe_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.</p>
    pub fn infrastructure_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.infrastructure_configuration_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration associated with this image pipeline.</p>
    pub fn distribution_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.distribution_configuration_arn.as_deref()
    }
    /// <p>The image tests configuration of the image pipeline.</p>
    pub fn image_tests_configuration(&self) -> ::std::option::Option<&crate::types::ImageTestsConfiguration> {
        self.image_tests_configuration.as_ref()
    }
    /// <p>The schedule of the image pipeline.</p>
    pub fn schedule(&self) -> ::std::option::Option<&crate::types::Schedule> {
        self.schedule.as_ref()
    }
    /// <p>The status of the image pipeline.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::PipelineStatus> {
        self.status.as_ref()
    }
    /// <p>The date on which this image pipeline was created.</p>
    pub fn date_created(&self) -> ::std::option::Option<&str> {
        self.date_created.as_deref()
    }
    /// <p>The date on which this image pipeline was last updated.</p>
    pub fn date_updated(&self) -> ::std::option::Option<&str> {
        self.date_updated.as_deref()
    }
    /// <p>This is no longer supported, and does not return a value.</p>
    pub fn date_last_run(&self) -> ::std::option::Option<&str> {
        self.date_last_run.as_deref()
    }
    /// <p>The next date when the pipeline is scheduled to run.</p>
    pub fn date_next_run(&self) -> ::std::option::Option<&str> {
        self.date_next_run.as_deref()
    }
    /// <p>The tags of this image pipeline.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>Contains settings for vulnerability scans.</p>
    pub fn image_scanning_configuration(&self) -> ::std::option::Option<&crate::types::ImageScanningConfiguration> {
        self.image_scanning_configuration.as_ref()
    }
    /// <p>The name or Amazon Resource Name (ARN) for the IAM role you create that grants Image Builder access to perform workflow actions.</p>
    pub fn execution_role(&self) -> ::std::option::Option<&str> {
        self.execution_role.as_deref()
    }
    /// <p>Contains the workflows that run for the image pipeline.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.workflows.is_none()`.
    pub fn workflows(&self) -> &[crate::types::WorkflowConfiguration] {
        self.workflows.as_deref().unwrap_or_default()
    }
}
impl ImagePipeline {
    /// Creates a new builder-style object to manufacture [`ImagePipeline`](crate::types::ImagePipeline).
    pub fn builder() -> crate::types::builders::ImagePipelineBuilder {
        crate::types::builders::ImagePipelineBuilder::default()
    }
}

/// A builder for [`ImagePipeline`](crate::types::ImagePipeline).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImagePipelineBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) platform: ::std::option::Option<crate::types::Platform>,
    pub(crate) enhanced_image_metadata_enabled: ::std::option::Option<bool>,
    pub(crate) image_recipe_arn: ::std::option::Option<::std::string::String>,
    pub(crate) container_recipe_arn: ::std::option::Option<::std::string::String>,
    pub(crate) infrastructure_configuration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) distribution_configuration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) image_tests_configuration: ::std::option::Option<crate::types::ImageTestsConfiguration>,
    pub(crate) schedule: ::std::option::Option<crate::types::Schedule>,
    pub(crate) status: ::std::option::Option<crate::types::PipelineStatus>,
    pub(crate) date_created: ::std::option::Option<::std::string::String>,
    pub(crate) date_updated: ::std::option::Option<::std::string::String>,
    pub(crate) date_last_run: ::std::option::Option<::std::string::String>,
    pub(crate) date_next_run: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) image_scanning_configuration: ::std::option::Option<crate::types::ImageScanningConfiguration>,
    pub(crate) execution_role: ::std::option::Option<::std::string::String>,
    pub(crate) workflows: ::std::option::Option<::std::vec::Vec<crate::types::WorkflowConfiguration>>,
}
impl ImagePipelineBuilder {
    /// <p>The Amazon Resource Name (ARN) of the image pipeline.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the image pipeline.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the image pipeline.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the image pipeline.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the image pipeline.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the image pipeline.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
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
    /// <p>The platform of the image pipeline.</p>
    pub fn platform(mut self, input: crate::types::Platform) -> Self {
        self.platform = ::std::option::Option::Some(input);
        self
    }
    /// <p>The platform of the image pipeline.</p>
    pub fn set_platform(mut self, input: ::std::option::Option<crate::types::Platform>) -> Self {
        self.platform = input;
        self
    }
    /// <p>The platform of the image pipeline.</p>
    pub fn get_platform(&self) -> &::std::option::Option<crate::types::Platform> {
        &self.platform
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
    /// <p>The Amazon Resource Name (ARN) of the image recipe associated with this image pipeline.</p>
    pub fn image_recipe_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_recipe_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the image recipe associated with this image pipeline.</p>
    pub fn set_image_recipe_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_recipe_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the image recipe associated with this image pipeline.</p>
    pub fn get_image_recipe_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_recipe_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.</p>
    pub fn container_recipe_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.container_recipe_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.</p>
    pub fn set_container_recipe_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.container_recipe_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.</p>
    pub fn get_container_recipe_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.container_recipe_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.</p>
    pub fn infrastructure_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.infrastructure_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.</p>
    pub fn set_infrastructure_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.infrastructure_configuration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.</p>
    pub fn get_infrastructure_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.infrastructure_configuration_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration associated with this image pipeline.</p>
    pub fn distribution_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.distribution_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration associated with this image pipeline.</p>
    pub fn set_distribution_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.distribution_configuration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration associated with this image pipeline.</p>
    pub fn get_distribution_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.distribution_configuration_arn
    }
    /// <p>The image tests configuration of the image pipeline.</p>
    pub fn image_tests_configuration(mut self, input: crate::types::ImageTestsConfiguration) -> Self {
        self.image_tests_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The image tests configuration of the image pipeline.</p>
    pub fn set_image_tests_configuration(mut self, input: ::std::option::Option<crate::types::ImageTestsConfiguration>) -> Self {
        self.image_tests_configuration = input;
        self
    }
    /// <p>The image tests configuration of the image pipeline.</p>
    pub fn get_image_tests_configuration(&self) -> &::std::option::Option<crate::types::ImageTestsConfiguration> {
        &self.image_tests_configuration
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
    /// <p>The date on which this image pipeline was created.</p>
    pub fn date_created(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.date_created = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date on which this image pipeline was created.</p>
    pub fn set_date_created(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.date_created = input;
        self
    }
    /// <p>The date on which this image pipeline was created.</p>
    pub fn get_date_created(&self) -> &::std::option::Option<::std::string::String> {
        &self.date_created
    }
    /// <p>The date on which this image pipeline was last updated.</p>
    pub fn date_updated(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.date_updated = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date on which this image pipeline was last updated.</p>
    pub fn set_date_updated(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.date_updated = input;
        self
    }
    /// <p>The date on which this image pipeline was last updated.</p>
    pub fn get_date_updated(&self) -> &::std::option::Option<::std::string::String> {
        &self.date_updated
    }
    /// <p>This is no longer supported, and does not return a value.</p>
    pub fn date_last_run(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.date_last_run = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This is no longer supported, and does not return a value.</p>
    pub fn set_date_last_run(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.date_last_run = input;
        self
    }
    /// <p>This is no longer supported, and does not return a value.</p>
    pub fn get_date_last_run(&self) -> &::std::option::Option<::std::string::String> {
        &self.date_last_run
    }
    /// <p>The next date when the pipeline is scheduled to run.</p>
    pub fn date_next_run(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.date_next_run = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next date when the pipeline is scheduled to run.</p>
    pub fn set_date_next_run(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.date_next_run = input;
        self
    }
    /// <p>The next date when the pipeline is scheduled to run.</p>
    pub fn get_date_next_run(&self) -> &::std::option::Option<::std::string::String> {
        &self.date_next_run
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags of this image pipeline.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags of this image pipeline.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags of this image pipeline.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
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
    /// Appends an item to `workflows`.
    ///
    /// To override the contents of this collection use [`set_workflows`](Self::set_workflows).
    ///
    /// <p>Contains the workflows that run for the image pipeline.</p>
    pub fn workflows(mut self, input: crate::types::WorkflowConfiguration) -> Self {
        let mut v = self.workflows.unwrap_or_default();
        v.push(input);
        self.workflows = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains the workflows that run for the image pipeline.</p>
    pub fn set_workflows(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::WorkflowConfiguration>>) -> Self {
        self.workflows = input;
        self
    }
    /// <p>Contains the workflows that run for the image pipeline.</p>
    pub fn get_workflows(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::WorkflowConfiguration>> {
        &self.workflows
    }
    /// Consumes the builder and constructs a [`ImagePipeline`](crate::types::ImagePipeline).
    pub fn build(self) -> crate::types::ImagePipeline {
        crate::types::ImagePipeline {
            arn: self.arn,
            name: self.name,
            description: self.description,
            platform: self.platform,
            enhanced_image_metadata_enabled: self.enhanced_image_metadata_enabled,
            image_recipe_arn: self.image_recipe_arn,
            container_recipe_arn: self.container_recipe_arn,
            infrastructure_configuration_arn: self.infrastructure_configuration_arn,
            distribution_configuration_arn: self.distribution_configuration_arn,
            image_tests_configuration: self.image_tests_configuration,
            schedule: self.schedule,
            status: self.status,
            date_created: self.date_created,
            date_updated: self.date_updated,
            date_last_run: self.date_last_run,
            date_next_run: self.date_next_run,
            tags: self.tags,
            image_scanning_configuration: self.image_scanning_configuration,
            execution_role: self.execution_role,
            workflows: self.workflows,
        }
    }
}
