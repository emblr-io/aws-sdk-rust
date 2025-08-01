// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateExperimentTemplateInput {
    /// <p>The ID of the experiment template.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>A description for the template.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The stop conditions for the experiment.</p>
    pub stop_conditions: ::std::option::Option<::std::vec::Vec<crate::types::UpdateExperimentTemplateStopConditionInput>>,
    /// <p>The targets for the experiment.</p>
    pub targets: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::UpdateExperimentTemplateTargetInput>>,
    /// <p>The actions for the experiment.</p>
    pub actions: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::UpdateExperimentTemplateActionInputItem>>,
    /// <p>The Amazon Resource Name (ARN) of an IAM role that grants the FIS service permission to perform service actions on your behalf.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The configuration for experiment logging.</p>
    pub log_configuration: ::std::option::Option<crate::types::UpdateExperimentTemplateLogConfigurationInput>,
    /// <p>The experiment options for the experiment template.</p>
    pub experiment_options: ::std::option::Option<crate::types::UpdateExperimentTemplateExperimentOptionsInput>,
    /// <p>The experiment report configuration for the experiment template.</p>
    pub experiment_report_configuration: ::std::option::Option<crate::types::UpdateExperimentTemplateReportConfigurationInput>,
}
impl UpdateExperimentTemplateInput {
    /// <p>The ID of the experiment template.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>A description for the template.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The stop conditions for the experiment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.stop_conditions.is_none()`.
    pub fn stop_conditions(&self) -> &[crate::types::UpdateExperimentTemplateStopConditionInput] {
        self.stop_conditions.as_deref().unwrap_or_default()
    }
    /// <p>The targets for the experiment.</p>
    pub fn targets(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::UpdateExperimentTemplateTargetInput>> {
        self.targets.as_ref()
    }
    /// <p>The actions for the experiment.</p>
    pub fn actions(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::UpdateExperimentTemplateActionInputItem>> {
        self.actions.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that grants the FIS service permission to perform service actions on your behalf.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>The configuration for experiment logging.</p>
    pub fn log_configuration(&self) -> ::std::option::Option<&crate::types::UpdateExperimentTemplateLogConfigurationInput> {
        self.log_configuration.as_ref()
    }
    /// <p>The experiment options for the experiment template.</p>
    pub fn experiment_options(&self) -> ::std::option::Option<&crate::types::UpdateExperimentTemplateExperimentOptionsInput> {
        self.experiment_options.as_ref()
    }
    /// <p>The experiment report configuration for the experiment template.</p>
    pub fn experiment_report_configuration(&self) -> ::std::option::Option<&crate::types::UpdateExperimentTemplateReportConfigurationInput> {
        self.experiment_report_configuration.as_ref()
    }
}
impl UpdateExperimentTemplateInput {
    /// Creates a new builder-style object to manufacture [`UpdateExperimentTemplateInput`](crate::operation::update_experiment_template::UpdateExperimentTemplateInput).
    pub fn builder() -> crate::operation::update_experiment_template::builders::UpdateExperimentTemplateInputBuilder {
        crate::operation::update_experiment_template::builders::UpdateExperimentTemplateInputBuilder::default()
    }
}

/// A builder for [`UpdateExperimentTemplateInput`](crate::operation::update_experiment_template::UpdateExperimentTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateExperimentTemplateInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) stop_conditions: ::std::option::Option<::std::vec::Vec<crate::types::UpdateExperimentTemplateStopConditionInput>>,
    pub(crate) targets: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::UpdateExperimentTemplateTargetInput>>,
    pub(crate) actions:
        ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::UpdateExperimentTemplateActionInputItem>>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) log_configuration: ::std::option::Option<crate::types::UpdateExperimentTemplateLogConfigurationInput>,
    pub(crate) experiment_options: ::std::option::Option<crate::types::UpdateExperimentTemplateExperimentOptionsInput>,
    pub(crate) experiment_report_configuration: ::std::option::Option<crate::types::UpdateExperimentTemplateReportConfigurationInput>,
}
impl UpdateExperimentTemplateInputBuilder {
    /// <p>The ID of the experiment template.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the experiment template.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the experiment template.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A description for the template.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the template.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the template.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `stop_conditions`.
    ///
    /// To override the contents of this collection use [`set_stop_conditions`](Self::set_stop_conditions).
    ///
    /// <p>The stop conditions for the experiment.</p>
    pub fn stop_conditions(mut self, input: crate::types::UpdateExperimentTemplateStopConditionInput) -> Self {
        let mut v = self.stop_conditions.unwrap_or_default();
        v.push(input);
        self.stop_conditions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The stop conditions for the experiment.</p>
    pub fn set_stop_conditions(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::UpdateExperimentTemplateStopConditionInput>>,
    ) -> Self {
        self.stop_conditions = input;
        self
    }
    /// <p>The stop conditions for the experiment.</p>
    pub fn get_stop_conditions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UpdateExperimentTemplateStopConditionInput>> {
        &self.stop_conditions
    }
    /// Adds a key-value pair to `targets`.
    ///
    /// To override the contents of this collection use [`set_targets`](Self::set_targets).
    ///
    /// <p>The targets for the experiment.</p>
    pub fn targets(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::UpdateExperimentTemplateTargetInput) -> Self {
        let mut hash_map = self.targets.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.targets = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The targets for the experiment.</p>
    pub fn set_targets(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::UpdateExperimentTemplateTargetInput>>,
    ) -> Self {
        self.targets = input;
        self
    }
    /// <p>The targets for the experiment.</p>
    pub fn get_targets(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::UpdateExperimentTemplateTargetInput>> {
        &self.targets
    }
    /// Adds a key-value pair to `actions`.
    ///
    /// To override the contents of this collection use [`set_actions`](Self::set_actions).
    ///
    /// <p>The actions for the experiment.</p>
    pub fn actions(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::UpdateExperimentTemplateActionInputItem) -> Self {
        let mut hash_map = self.actions.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.actions = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The actions for the experiment.</p>
    pub fn set_actions(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::UpdateExperimentTemplateActionInputItem>>,
    ) -> Self {
        self.actions = input;
        self
    }
    /// <p>The actions for the experiment.</p>
    pub fn get_actions(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::UpdateExperimentTemplateActionInputItem>> {
        &self.actions
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that grants the FIS service permission to perform service actions on your behalf.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that grants the FIS service permission to perform service actions on your behalf.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that grants the FIS service permission to perform service actions on your behalf.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The configuration for experiment logging.</p>
    pub fn log_configuration(mut self, input: crate::types::UpdateExperimentTemplateLogConfigurationInput) -> Self {
        self.log_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for experiment logging.</p>
    pub fn set_log_configuration(mut self, input: ::std::option::Option<crate::types::UpdateExperimentTemplateLogConfigurationInput>) -> Self {
        self.log_configuration = input;
        self
    }
    /// <p>The configuration for experiment logging.</p>
    pub fn get_log_configuration(&self) -> &::std::option::Option<crate::types::UpdateExperimentTemplateLogConfigurationInput> {
        &self.log_configuration
    }
    /// <p>The experiment options for the experiment template.</p>
    pub fn experiment_options(mut self, input: crate::types::UpdateExperimentTemplateExperimentOptionsInput) -> Self {
        self.experiment_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The experiment options for the experiment template.</p>
    pub fn set_experiment_options(mut self, input: ::std::option::Option<crate::types::UpdateExperimentTemplateExperimentOptionsInput>) -> Self {
        self.experiment_options = input;
        self
    }
    /// <p>The experiment options for the experiment template.</p>
    pub fn get_experiment_options(&self) -> &::std::option::Option<crate::types::UpdateExperimentTemplateExperimentOptionsInput> {
        &self.experiment_options
    }
    /// <p>The experiment report configuration for the experiment template.</p>
    pub fn experiment_report_configuration(mut self, input: crate::types::UpdateExperimentTemplateReportConfigurationInput) -> Self {
        self.experiment_report_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The experiment report configuration for the experiment template.</p>
    pub fn set_experiment_report_configuration(
        mut self,
        input: ::std::option::Option<crate::types::UpdateExperimentTemplateReportConfigurationInput>,
    ) -> Self {
        self.experiment_report_configuration = input;
        self
    }
    /// <p>The experiment report configuration for the experiment template.</p>
    pub fn get_experiment_report_configuration(&self) -> &::std::option::Option<crate::types::UpdateExperimentTemplateReportConfigurationInput> {
        &self.experiment_report_configuration
    }
    /// Consumes the builder and constructs a [`UpdateExperimentTemplateInput`](crate::operation::update_experiment_template::UpdateExperimentTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_experiment_template::UpdateExperimentTemplateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_experiment_template::UpdateExperimentTemplateInput {
            id: self.id,
            description: self.description,
            stop_conditions: self.stop_conditions,
            targets: self.targets,
            actions: self.actions,
            role_arn: self.role_arn,
            log_configuration: self.log_configuration,
            experiment_options: self.experiment_options,
            experiment_report_configuration: self.experiment_report_configuration,
        })
    }
}
