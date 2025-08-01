// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDashboardInput {
    /// <p>The ID of the Amazon Web Services account where you want to create the dashboard.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID for the dashboard, also added to the IAM policy.</p>
    pub dashboard_id: ::std::option::Option<::std::string::String>,
    /// <p>The display name of the dashboard.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The parameters for the creation of the dashboard, which you want to use to override the default settings. A dashboard can have any type of parameters, and some parameters might accept multiple values.</p>
    pub parameters: ::std::option::Option<crate::types::Parameters>,
    /// <p>A structure that contains the permissions of the dashboard. You can use this structure for granting permissions by providing a list of IAM action information for each principal ARN.</p>
    /// <p>To specify no permissions, omit the permissions list.</p>
    pub permissions: ::std::option::Option<::std::vec::Vec<crate::types::ResourcePermission>>,
    /// <p>The entity that you are using as a source when you create the dashboard. In <code>SourceEntity</code>, you specify the type of object you're using as source. You can only create a dashboard from a template, so you use a <code>SourceTemplate</code> entity. If you need to create a dashboard from an analysis, first convert the analysis to a template by using the <code> <a href="https://docs.aws.amazon.com/quicksight/latest/APIReference/API_CreateTemplate.html">CreateTemplate</a> </code> API operation. For <code>SourceTemplate</code>, specify the Amazon Resource Name (ARN) of the source template. The <code>SourceTemplate</code>ARN can contain any Amazon Web Services account and any Amazon QuickSight-supported Amazon Web Services Region.</p>
    /// <p>Use the <code>DataSetReferences</code> entity within <code>SourceTemplate</code> to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.</p>
    /// <p>Either a <code>SourceEntity</code> or a <code>Definition</code> must be provided in order for the request to be valid.</p>
    pub source_entity: ::std::option::Option<crate::types::DashboardSourceEntity>,
    /// <p>Contains a map of the key-value pairs for the resource tag or tags assigned to the dashboard.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>A description for the first version of the dashboard being created.</p>
    pub version_description: ::std::option::Option<::std::string::String>,
    /// <p>Options for publishing the dashboard when you create it:</p>
    /// <ul>
    /// <li>
    /// <p><code>AvailabilityStatus</code> for <code>AdHocFilteringOption</code> - This status can be either <code>ENABLED</code> or <code>DISABLED</code>. When this is set to <code>DISABLED</code>, Amazon QuickSight disables the left filter pane on the published dashboard, which can be used for ad hoc (one-time) filtering. This option is <code>ENABLED</code> by default.</p></li>
    /// <li>
    /// <p><code>AvailabilityStatus</code> for <code>ExportToCSVOption</code> - This status can be either <code>ENABLED</code> or <code>DISABLED</code>. The visual option to export data to .CSV format isn't enabled when this is set to <code>DISABLED</code>. This option is <code>ENABLED</code> by default.</p></li>
    /// <li>
    /// <p><code>VisibilityState</code> for <code>SheetControlsOption</code> - This visibility state can be either <code>COLLAPSED</code> or <code>EXPANDED</code>. This option is <code>COLLAPSED</code> by default.</p></li>
    /// </ul>
    pub dashboard_publish_options: ::std::option::Option<crate::types::DashboardPublishOptions>,
    /// <p>The Amazon Resource Name (ARN) of the theme that is being used for this dashboard. If you add a value for this field, it overrides the value that is used in the source entity. The theme ARN must exist in the same Amazon Web Services account where you create the dashboard.</p>
    pub theme_arn: ::std::option::Option<::std::string::String>,
    /// <p>The definition of a dashboard.</p>
    /// <p>A definition is the data model of all features in a Dashboard, Template, or Analysis.</p>
    /// <p>Either a <code>SourceEntity</code> or a <code>Definition</code> must be provided in order for the request to be valid.</p>
    pub definition: ::std::option::Option<crate::types::DashboardVersionDefinition>,
    /// <p>The option to relax the validation needed to create a dashboard with definition objects. This option skips the validation step for specific errors.</p>
    pub validation_strategy: ::std::option::Option<crate::types::ValidationStrategy>,
    /// <p>When you create the dashboard, Amazon QuickSight adds the dashboard to these folders.</p>
    pub folder_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A structure that contains the permissions of a shareable link to the dashboard.</p>
    pub link_sharing_configuration: ::std::option::Option<crate::types::LinkSharingConfiguration>,
    /// <p>A list of analysis Amazon Resource Names (ARNs) to be linked to the dashboard.</p>
    pub link_entities: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CreateDashboardInput {
    /// <p>The ID of the Amazon Web Services account where you want to create the dashboard.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The ID for the dashboard, also added to the IAM policy.</p>
    pub fn dashboard_id(&self) -> ::std::option::Option<&str> {
        self.dashboard_id.as_deref()
    }
    /// <p>The display name of the dashboard.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The parameters for the creation of the dashboard, which you want to use to override the default settings. A dashboard can have any type of parameters, and some parameters might accept multiple values.</p>
    pub fn parameters(&self) -> ::std::option::Option<&crate::types::Parameters> {
        self.parameters.as_ref()
    }
    /// <p>A structure that contains the permissions of the dashboard. You can use this structure for granting permissions by providing a list of IAM action information for each principal ARN.</p>
    /// <p>To specify no permissions, omit the permissions list.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.permissions.is_none()`.
    pub fn permissions(&self) -> &[crate::types::ResourcePermission] {
        self.permissions.as_deref().unwrap_or_default()
    }
    /// <p>The entity that you are using as a source when you create the dashboard. In <code>SourceEntity</code>, you specify the type of object you're using as source. You can only create a dashboard from a template, so you use a <code>SourceTemplate</code> entity. If you need to create a dashboard from an analysis, first convert the analysis to a template by using the <code> <a href="https://docs.aws.amazon.com/quicksight/latest/APIReference/API_CreateTemplate.html">CreateTemplate</a> </code> API operation. For <code>SourceTemplate</code>, specify the Amazon Resource Name (ARN) of the source template. The <code>SourceTemplate</code>ARN can contain any Amazon Web Services account and any Amazon QuickSight-supported Amazon Web Services Region.</p>
    /// <p>Use the <code>DataSetReferences</code> entity within <code>SourceTemplate</code> to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.</p>
    /// <p>Either a <code>SourceEntity</code> or a <code>Definition</code> must be provided in order for the request to be valid.</p>
    pub fn source_entity(&self) -> ::std::option::Option<&crate::types::DashboardSourceEntity> {
        self.source_entity.as_ref()
    }
    /// <p>Contains a map of the key-value pairs for the resource tag or tags assigned to the dashboard.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>A description for the first version of the dashboard being created.</p>
    pub fn version_description(&self) -> ::std::option::Option<&str> {
        self.version_description.as_deref()
    }
    /// <p>Options for publishing the dashboard when you create it:</p>
    /// <ul>
    /// <li>
    /// <p><code>AvailabilityStatus</code> for <code>AdHocFilteringOption</code> - This status can be either <code>ENABLED</code> or <code>DISABLED</code>. When this is set to <code>DISABLED</code>, Amazon QuickSight disables the left filter pane on the published dashboard, which can be used for ad hoc (one-time) filtering. This option is <code>ENABLED</code> by default.</p></li>
    /// <li>
    /// <p><code>AvailabilityStatus</code> for <code>ExportToCSVOption</code> - This status can be either <code>ENABLED</code> or <code>DISABLED</code>. The visual option to export data to .CSV format isn't enabled when this is set to <code>DISABLED</code>. This option is <code>ENABLED</code> by default.</p></li>
    /// <li>
    /// <p><code>VisibilityState</code> for <code>SheetControlsOption</code> - This visibility state can be either <code>COLLAPSED</code> or <code>EXPANDED</code>. This option is <code>COLLAPSED</code> by default.</p></li>
    /// </ul>
    pub fn dashboard_publish_options(&self) -> ::std::option::Option<&crate::types::DashboardPublishOptions> {
        self.dashboard_publish_options.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the theme that is being used for this dashboard. If you add a value for this field, it overrides the value that is used in the source entity. The theme ARN must exist in the same Amazon Web Services account where you create the dashboard.</p>
    pub fn theme_arn(&self) -> ::std::option::Option<&str> {
        self.theme_arn.as_deref()
    }
    /// <p>The definition of a dashboard.</p>
    /// <p>A definition is the data model of all features in a Dashboard, Template, or Analysis.</p>
    /// <p>Either a <code>SourceEntity</code> or a <code>Definition</code> must be provided in order for the request to be valid.</p>
    pub fn definition(&self) -> ::std::option::Option<&crate::types::DashboardVersionDefinition> {
        self.definition.as_ref()
    }
    /// <p>The option to relax the validation needed to create a dashboard with definition objects. This option skips the validation step for specific errors.</p>
    pub fn validation_strategy(&self) -> ::std::option::Option<&crate::types::ValidationStrategy> {
        self.validation_strategy.as_ref()
    }
    /// <p>When you create the dashboard, Amazon QuickSight adds the dashboard to these folders.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.folder_arns.is_none()`.
    pub fn folder_arns(&self) -> &[::std::string::String] {
        self.folder_arns.as_deref().unwrap_or_default()
    }
    /// <p>A structure that contains the permissions of a shareable link to the dashboard.</p>
    pub fn link_sharing_configuration(&self) -> ::std::option::Option<&crate::types::LinkSharingConfiguration> {
        self.link_sharing_configuration.as_ref()
    }
    /// <p>A list of analysis Amazon Resource Names (ARNs) to be linked to the dashboard.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.link_entities.is_none()`.
    pub fn link_entities(&self) -> &[::std::string::String] {
        self.link_entities.as_deref().unwrap_or_default()
    }
}
impl CreateDashboardInput {
    /// Creates a new builder-style object to manufacture [`CreateDashboardInput`](crate::operation::create_dashboard::CreateDashboardInput).
    pub fn builder() -> crate::operation::create_dashboard::builders::CreateDashboardInputBuilder {
        crate::operation::create_dashboard::builders::CreateDashboardInputBuilder::default()
    }
}

/// A builder for [`CreateDashboardInput`](crate::operation::create_dashboard::CreateDashboardInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDashboardInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) dashboard_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<crate::types::Parameters>,
    pub(crate) permissions: ::std::option::Option<::std::vec::Vec<crate::types::ResourcePermission>>,
    pub(crate) source_entity: ::std::option::Option<crate::types::DashboardSourceEntity>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) version_description: ::std::option::Option<::std::string::String>,
    pub(crate) dashboard_publish_options: ::std::option::Option<crate::types::DashboardPublishOptions>,
    pub(crate) theme_arn: ::std::option::Option<::std::string::String>,
    pub(crate) definition: ::std::option::Option<crate::types::DashboardVersionDefinition>,
    pub(crate) validation_strategy: ::std::option::Option<crate::types::ValidationStrategy>,
    pub(crate) folder_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) link_sharing_configuration: ::std::option::Option<crate::types::LinkSharingConfiguration>,
    pub(crate) link_entities: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CreateDashboardInputBuilder {
    /// <p>The ID of the Amazon Web Services account where you want to create the dashboard.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account where you want to create the dashboard.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account where you want to create the dashboard.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The ID for the dashboard, also added to the IAM policy.</p>
    /// This field is required.
    pub fn dashboard_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dashboard_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the dashboard, also added to the IAM policy.</p>
    pub fn set_dashboard_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dashboard_id = input;
        self
    }
    /// <p>The ID for the dashboard, also added to the IAM policy.</p>
    pub fn get_dashboard_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.dashboard_id
    }
    /// <p>The display name of the dashboard.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of the dashboard.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The display name of the dashboard.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The parameters for the creation of the dashboard, which you want to use to override the default settings. A dashboard can have any type of parameters, and some parameters might accept multiple values.</p>
    pub fn parameters(mut self, input: crate::types::Parameters) -> Self {
        self.parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>The parameters for the creation of the dashboard, which you want to use to override the default settings. A dashboard can have any type of parameters, and some parameters might accept multiple values.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<crate::types::Parameters>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The parameters for the creation of the dashboard, which you want to use to override the default settings. A dashboard can have any type of parameters, and some parameters might accept multiple values.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<crate::types::Parameters> {
        &self.parameters
    }
    /// Appends an item to `permissions`.
    ///
    /// To override the contents of this collection use [`set_permissions`](Self::set_permissions).
    ///
    /// <p>A structure that contains the permissions of the dashboard. You can use this structure for granting permissions by providing a list of IAM action information for each principal ARN.</p>
    /// <p>To specify no permissions, omit the permissions list.</p>
    pub fn permissions(mut self, input: crate::types::ResourcePermission) -> Self {
        let mut v = self.permissions.unwrap_or_default();
        v.push(input);
        self.permissions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A structure that contains the permissions of the dashboard. You can use this structure for granting permissions by providing a list of IAM action information for each principal ARN.</p>
    /// <p>To specify no permissions, omit the permissions list.</p>
    pub fn set_permissions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResourcePermission>>) -> Self {
        self.permissions = input;
        self
    }
    /// <p>A structure that contains the permissions of the dashboard. You can use this structure for granting permissions by providing a list of IAM action information for each principal ARN.</p>
    /// <p>To specify no permissions, omit the permissions list.</p>
    pub fn get_permissions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResourcePermission>> {
        &self.permissions
    }
    /// <p>The entity that you are using as a source when you create the dashboard. In <code>SourceEntity</code>, you specify the type of object you're using as source. You can only create a dashboard from a template, so you use a <code>SourceTemplate</code> entity. If you need to create a dashboard from an analysis, first convert the analysis to a template by using the <code> <a href="https://docs.aws.amazon.com/quicksight/latest/APIReference/API_CreateTemplate.html">CreateTemplate</a> </code> API operation. For <code>SourceTemplate</code>, specify the Amazon Resource Name (ARN) of the source template. The <code>SourceTemplate</code>ARN can contain any Amazon Web Services account and any Amazon QuickSight-supported Amazon Web Services Region.</p>
    /// <p>Use the <code>DataSetReferences</code> entity within <code>SourceTemplate</code> to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.</p>
    /// <p>Either a <code>SourceEntity</code> or a <code>Definition</code> must be provided in order for the request to be valid.</p>
    pub fn source_entity(mut self, input: crate::types::DashboardSourceEntity) -> Self {
        self.source_entity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The entity that you are using as a source when you create the dashboard. In <code>SourceEntity</code>, you specify the type of object you're using as source. You can only create a dashboard from a template, so you use a <code>SourceTemplate</code> entity. If you need to create a dashboard from an analysis, first convert the analysis to a template by using the <code> <a href="https://docs.aws.amazon.com/quicksight/latest/APIReference/API_CreateTemplate.html">CreateTemplate</a> </code> API operation. For <code>SourceTemplate</code>, specify the Amazon Resource Name (ARN) of the source template. The <code>SourceTemplate</code>ARN can contain any Amazon Web Services account and any Amazon QuickSight-supported Amazon Web Services Region.</p>
    /// <p>Use the <code>DataSetReferences</code> entity within <code>SourceTemplate</code> to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.</p>
    /// <p>Either a <code>SourceEntity</code> or a <code>Definition</code> must be provided in order for the request to be valid.</p>
    pub fn set_source_entity(mut self, input: ::std::option::Option<crate::types::DashboardSourceEntity>) -> Self {
        self.source_entity = input;
        self
    }
    /// <p>The entity that you are using as a source when you create the dashboard. In <code>SourceEntity</code>, you specify the type of object you're using as source. You can only create a dashboard from a template, so you use a <code>SourceTemplate</code> entity. If you need to create a dashboard from an analysis, first convert the analysis to a template by using the <code> <a href="https://docs.aws.amazon.com/quicksight/latest/APIReference/API_CreateTemplate.html">CreateTemplate</a> </code> API operation. For <code>SourceTemplate</code>, specify the Amazon Resource Name (ARN) of the source template. The <code>SourceTemplate</code>ARN can contain any Amazon Web Services account and any Amazon QuickSight-supported Amazon Web Services Region.</p>
    /// <p>Use the <code>DataSetReferences</code> entity within <code>SourceTemplate</code> to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.</p>
    /// <p>Either a <code>SourceEntity</code> or a <code>Definition</code> must be provided in order for the request to be valid.</p>
    pub fn get_source_entity(&self) -> &::std::option::Option<crate::types::DashboardSourceEntity> {
        &self.source_entity
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Contains a map of the key-value pairs for the resource tag or tags assigned to the dashboard.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains a map of the key-value pairs for the resource tag or tags assigned to the dashboard.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Contains a map of the key-value pairs for the resource tag or tags assigned to the dashboard.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>A description for the first version of the dashboard being created.</p>
    pub fn version_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the first version of the dashboard being created.</p>
    pub fn set_version_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_description = input;
        self
    }
    /// <p>A description for the first version of the dashboard being created.</p>
    pub fn get_version_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_description
    }
    /// <p>Options for publishing the dashboard when you create it:</p>
    /// <ul>
    /// <li>
    /// <p><code>AvailabilityStatus</code> for <code>AdHocFilteringOption</code> - This status can be either <code>ENABLED</code> or <code>DISABLED</code>. When this is set to <code>DISABLED</code>, Amazon QuickSight disables the left filter pane on the published dashboard, which can be used for ad hoc (one-time) filtering. This option is <code>ENABLED</code> by default.</p></li>
    /// <li>
    /// <p><code>AvailabilityStatus</code> for <code>ExportToCSVOption</code> - This status can be either <code>ENABLED</code> or <code>DISABLED</code>. The visual option to export data to .CSV format isn't enabled when this is set to <code>DISABLED</code>. This option is <code>ENABLED</code> by default.</p></li>
    /// <li>
    /// <p><code>VisibilityState</code> for <code>SheetControlsOption</code> - This visibility state can be either <code>COLLAPSED</code> or <code>EXPANDED</code>. This option is <code>COLLAPSED</code> by default.</p></li>
    /// </ul>
    pub fn dashboard_publish_options(mut self, input: crate::types::DashboardPublishOptions) -> Self {
        self.dashboard_publish_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Options for publishing the dashboard when you create it:</p>
    /// <ul>
    /// <li>
    /// <p><code>AvailabilityStatus</code> for <code>AdHocFilteringOption</code> - This status can be either <code>ENABLED</code> or <code>DISABLED</code>. When this is set to <code>DISABLED</code>, Amazon QuickSight disables the left filter pane on the published dashboard, which can be used for ad hoc (one-time) filtering. This option is <code>ENABLED</code> by default.</p></li>
    /// <li>
    /// <p><code>AvailabilityStatus</code> for <code>ExportToCSVOption</code> - This status can be either <code>ENABLED</code> or <code>DISABLED</code>. The visual option to export data to .CSV format isn't enabled when this is set to <code>DISABLED</code>. This option is <code>ENABLED</code> by default.</p></li>
    /// <li>
    /// <p><code>VisibilityState</code> for <code>SheetControlsOption</code> - This visibility state can be either <code>COLLAPSED</code> or <code>EXPANDED</code>. This option is <code>COLLAPSED</code> by default.</p></li>
    /// </ul>
    pub fn set_dashboard_publish_options(mut self, input: ::std::option::Option<crate::types::DashboardPublishOptions>) -> Self {
        self.dashboard_publish_options = input;
        self
    }
    /// <p>Options for publishing the dashboard when you create it:</p>
    /// <ul>
    /// <li>
    /// <p><code>AvailabilityStatus</code> for <code>AdHocFilteringOption</code> - This status can be either <code>ENABLED</code> or <code>DISABLED</code>. When this is set to <code>DISABLED</code>, Amazon QuickSight disables the left filter pane on the published dashboard, which can be used for ad hoc (one-time) filtering. This option is <code>ENABLED</code> by default.</p></li>
    /// <li>
    /// <p><code>AvailabilityStatus</code> for <code>ExportToCSVOption</code> - This status can be either <code>ENABLED</code> or <code>DISABLED</code>. The visual option to export data to .CSV format isn't enabled when this is set to <code>DISABLED</code>. This option is <code>ENABLED</code> by default.</p></li>
    /// <li>
    /// <p><code>VisibilityState</code> for <code>SheetControlsOption</code> - This visibility state can be either <code>COLLAPSED</code> or <code>EXPANDED</code>. This option is <code>COLLAPSED</code> by default.</p></li>
    /// </ul>
    pub fn get_dashboard_publish_options(&self) -> &::std::option::Option<crate::types::DashboardPublishOptions> {
        &self.dashboard_publish_options
    }
    /// <p>The Amazon Resource Name (ARN) of the theme that is being used for this dashboard. If you add a value for this field, it overrides the value that is used in the source entity. The theme ARN must exist in the same Amazon Web Services account where you create the dashboard.</p>
    pub fn theme_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.theme_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the theme that is being used for this dashboard. If you add a value for this field, it overrides the value that is used in the source entity. The theme ARN must exist in the same Amazon Web Services account where you create the dashboard.</p>
    pub fn set_theme_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.theme_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the theme that is being used for this dashboard. If you add a value for this field, it overrides the value that is used in the source entity. The theme ARN must exist in the same Amazon Web Services account where you create the dashboard.</p>
    pub fn get_theme_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.theme_arn
    }
    /// <p>The definition of a dashboard.</p>
    /// <p>A definition is the data model of all features in a Dashboard, Template, or Analysis.</p>
    /// <p>Either a <code>SourceEntity</code> or a <code>Definition</code> must be provided in order for the request to be valid.</p>
    pub fn definition(mut self, input: crate::types::DashboardVersionDefinition) -> Self {
        self.definition = ::std::option::Option::Some(input);
        self
    }
    /// <p>The definition of a dashboard.</p>
    /// <p>A definition is the data model of all features in a Dashboard, Template, or Analysis.</p>
    /// <p>Either a <code>SourceEntity</code> or a <code>Definition</code> must be provided in order for the request to be valid.</p>
    pub fn set_definition(mut self, input: ::std::option::Option<crate::types::DashboardVersionDefinition>) -> Self {
        self.definition = input;
        self
    }
    /// <p>The definition of a dashboard.</p>
    /// <p>A definition is the data model of all features in a Dashboard, Template, or Analysis.</p>
    /// <p>Either a <code>SourceEntity</code> or a <code>Definition</code> must be provided in order for the request to be valid.</p>
    pub fn get_definition(&self) -> &::std::option::Option<crate::types::DashboardVersionDefinition> {
        &self.definition
    }
    /// <p>The option to relax the validation needed to create a dashboard with definition objects. This option skips the validation step for specific errors.</p>
    pub fn validation_strategy(mut self, input: crate::types::ValidationStrategy) -> Self {
        self.validation_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The option to relax the validation needed to create a dashboard with definition objects. This option skips the validation step for specific errors.</p>
    pub fn set_validation_strategy(mut self, input: ::std::option::Option<crate::types::ValidationStrategy>) -> Self {
        self.validation_strategy = input;
        self
    }
    /// <p>The option to relax the validation needed to create a dashboard with definition objects. This option skips the validation step for specific errors.</p>
    pub fn get_validation_strategy(&self) -> &::std::option::Option<crate::types::ValidationStrategy> {
        &self.validation_strategy
    }
    /// Appends an item to `folder_arns`.
    ///
    /// To override the contents of this collection use [`set_folder_arns`](Self::set_folder_arns).
    ///
    /// <p>When you create the dashboard, Amazon QuickSight adds the dashboard to these folders.</p>
    pub fn folder_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.folder_arns.unwrap_or_default();
        v.push(input.into());
        self.folder_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>When you create the dashboard, Amazon QuickSight adds the dashboard to these folders.</p>
    pub fn set_folder_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.folder_arns = input;
        self
    }
    /// <p>When you create the dashboard, Amazon QuickSight adds the dashboard to these folders.</p>
    pub fn get_folder_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.folder_arns
    }
    /// <p>A structure that contains the permissions of a shareable link to the dashboard.</p>
    pub fn link_sharing_configuration(mut self, input: crate::types::LinkSharingConfiguration) -> Self {
        self.link_sharing_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that contains the permissions of a shareable link to the dashboard.</p>
    pub fn set_link_sharing_configuration(mut self, input: ::std::option::Option<crate::types::LinkSharingConfiguration>) -> Self {
        self.link_sharing_configuration = input;
        self
    }
    /// <p>A structure that contains the permissions of a shareable link to the dashboard.</p>
    pub fn get_link_sharing_configuration(&self) -> &::std::option::Option<crate::types::LinkSharingConfiguration> {
        &self.link_sharing_configuration
    }
    /// Appends an item to `link_entities`.
    ///
    /// To override the contents of this collection use [`set_link_entities`](Self::set_link_entities).
    ///
    /// <p>A list of analysis Amazon Resource Names (ARNs) to be linked to the dashboard.</p>
    pub fn link_entities(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.link_entities.unwrap_or_default();
        v.push(input.into());
        self.link_entities = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of analysis Amazon Resource Names (ARNs) to be linked to the dashboard.</p>
    pub fn set_link_entities(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.link_entities = input;
        self
    }
    /// <p>A list of analysis Amazon Resource Names (ARNs) to be linked to the dashboard.</p>
    pub fn get_link_entities(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.link_entities
    }
    /// Consumes the builder and constructs a [`CreateDashboardInput`](crate::operation::create_dashboard::CreateDashboardInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_dashboard::CreateDashboardInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_dashboard::CreateDashboardInput {
            aws_account_id: self.aws_account_id,
            dashboard_id: self.dashboard_id,
            name: self.name,
            parameters: self.parameters,
            permissions: self.permissions,
            source_entity: self.source_entity,
            tags: self.tags,
            version_description: self.version_description,
            dashboard_publish_options: self.dashboard_publish_options,
            theme_arn: self.theme_arn,
            definition: self.definition,
            validation_strategy: self.validation_strategy,
            folder_arns: self.folder_arns,
            link_sharing_configuration: self.link_sharing_configuration,
            link_entities: self.link_entities,
        })
    }
}
