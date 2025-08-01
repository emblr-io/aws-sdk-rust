// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <important>
/// <p>By default, all new solutions use automatic training. With automatic training, you incur training costs while your solution is active. To avoid unnecessary costs, when you are finished you can <a href="https://docs.aws.amazon.com/personalize/latest/dg/API_UpdateSolution.html">update the solution</a> to turn off automatic training. For information about training costs, see <a href="https://aws.amazon.com/personalize/pricing/">Amazon Personalize pricing</a>.</p>
/// </important>
/// <p>An object that provides information about a solution. A solution includes the custom recipe, customized parameters, and trained models (Solution Versions) that Amazon Personalize uses to generate recommendations.</p>
/// <p>After you create a solution, you can’t change its configuration. If you need to make changes, you can <a href="https://docs.aws.amazon.com/personalize/latest/dg/cloning-solution.html">clone the solution</a> with the Amazon Personalize console or create a new one.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Solution {
    /// <p>The name of the solution.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the solution.</p>
    pub solution_arn: ::std::option::Option<::std::string::String>,
    /// <p>Whether to perform hyperparameter optimization (HPO) on the chosen recipe. The default is <code>false</code>.</p>
    pub perform_hpo: bool,
    /// <important>
    /// <p>We don't recommend enabling automated machine learning. Instead, match your use case to the available Amazon Personalize recipes. For more information, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/determining-use-case.html">Determining your use case.</a></p>
    /// </important>
    /// <p>When true, Amazon Personalize performs a search for the best USER_PERSONALIZATION recipe from the list specified in the solution configuration (<code>recipeArn</code> must not be specified). When false (the default), Amazon Personalize uses <code>recipeArn</code> for training.</p>
    pub perform_auto_ml: bool,
    /// <p>Specifies whether the solution automatically creates solution versions. The default is <code>True</code> and the solution automatically creates new solution versions every 7 days.</p>
    /// <p>For more information about auto training, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/customizing-solution-config.html">Creating and configuring a solution</a>.</p>
    pub perform_auto_training: ::std::option::Option<bool>,
    /// <p>The ARN of the recipe used to create the solution. This is required when <code>performAutoML</code> is false.</p>
    pub recipe_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the dataset group that provides the training data.</p>
    pub dataset_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>The event type (for example, 'click' or 'like') that is used for training the model. If no <code>eventType</code> is provided, Amazon Personalize uses all interactions for training with equal weight regardless of type.</p>
    pub event_type: ::std::option::Option<::std::string::String>,
    /// <p>Describes the configuration properties for the solution.</p>
    pub solution_config: ::std::option::Option<crate::types::SolutionConfig>,
    /// <p>When <code>performAutoML</code> is true, specifies the best recipe found.</p>
    pub auto_ml_result: ::std::option::Option<crate::types::AutoMlResult>,
    /// <p>The status of the solution.</p>
    /// <p>A solution can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE PENDING &gt; CREATE IN_PROGRESS &gt; ACTIVE -or- CREATE FAILED</p></li>
    /// <li>
    /// <p>DELETE PENDING &gt; DELETE IN_PROGRESS</p></li>
    /// </ul>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>The creation date and time (in Unix time) of the solution.</p>
    pub creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time (in Unix time) that the solution was last updated.</p>
    pub last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Describes the latest version of the solution, including the status and the ARN.</p>
    pub latest_solution_version: ::std::option::Option<crate::types::SolutionVersionSummary>,
    /// <p>Provides a summary of the latest updates to the solution.</p>
    pub latest_solution_update: ::std::option::Option<crate::types::SolutionUpdateSummary>,
}
impl Solution {
    /// <p>The name of the solution.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The ARN of the solution.</p>
    pub fn solution_arn(&self) -> ::std::option::Option<&str> {
        self.solution_arn.as_deref()
    }
    /// <p>Whether to perform hyperparameter optimization (HPO) on the chosen recipe. The default is <code>false</code>.</p>
    pub fn perform_hpo(&self) -> bool {
        self.perform_hpo
    }
    /// <important>
    /// <p>We don't recommend enabling automated machine learning. Instead, match your use case to the available Amazon Personalize recipes. For more information, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/determining-use-case.html">Determining your use case.</a></p>
    /// </important>
    /// <p>When true, Amazon Personalize performs a search for the best USER_PERSONALIZATION recipe from the list specified in the solution configuration (<code>recipeArn</code> must not be specified). When false (the default), Amazon Personalize uses <code>recipeArn</code> for training.</p>
    pub fn perform_auto_ml(&self) -> bool {
        self.perform_auto_ml
    }
    /// <p>Specifies whether the solution automatically creates solution versions. The default is <code>True</code> and the solution automatically creates new solution versions every 7 days.</p>
    /// <p>For more information about auto training, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/customizing-solution-config.html">Creating and configuring a solution</a>.</p>
    pub fn perform_auto_training(&self) -> ::std::option::Option<bool> {
        self.perform_auto_training
    }
    /// <p>The ARN of the recipe used to create the solution. This is required when <code>performAutoML</code> is false.</p>
    pub fn recipe_arn(&self) -> ::std::option::Option<&str> {
        self.recipe_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the dataset group that provides the training data.</p>
    pub fn dataset_group_arn(&self) -> ::std::option::Option<&str> {
        self.dataset_group_arn.as_deref()
    }
    /// <p>The event type (for example, 'click' or 'like') that is used for training the model. If no <code>eventType</code> is provided, Amazon Personalize uses all interactions for training with equal weight regardless of type.</p>
    pub fn event_type(&self) -> ::std::option::Option<&str> {
        self.event_type.as_deref()
    }
    /// <p>Describes the configuration properties for the solution.</p>
    pub fn solution_config(&self) -> ::std::option::Option<&crate::types::SolutionConfig> {
        self.solution_config.as_ref()
    }
    /// <p>When <code>performAutoML</code> is true, specifies the best recipe found.</p>
    pub fn auto_ml_result(&self) -> ::std::option::Option<&crate::types::AutoMlResult> {
        self.auto_ml_result.as_ref()
    }
    /// <p>The status of the solution.</p>
    /// <p>A solution can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE PENDING &gt; CREATE IN_PROGRESS &gt; ACTIVE -or- CREATE FAILED</p></li>
    /// <li>
    /// <p>DELETE PENDING &gt; DELETE IN_PROGRESS</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>The creation date and time (in Unix time) of the solution.</p>
    pub fn creation_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date_time.as_ref()
    }
    /// <p>The date and time (in Unix time) that the solution was last updated.</p>
    pub fn last_updated_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_date_time.as_ref()
    }
    /// <p>Describes the latest version of the solution, including the status and the ARN.</p>
    pub fn latest_solution_version(&self) -> ::std::option::Option<&crate::types::SolutionVersionSummary> {
        self.latest_solution_version.as_ref()
    }
    /// <p>Provides a summary of the latest updates to the solution.</p>
    pub fn latest_solution_update(&self) -> ::std::option::Option<&crate::types::SolutionUpdateSummary> {
        self.latest_solution_update.as_ref()
    }
}
impl Solution {
    /// Creates a new builder-style object to manufacture [`Solution`](crate::types::Solution).
    pub fn builder() -> crate::types::builders::SolutionBuilder {
        crate::types::builders::SolutionBuilder::default()
    }
}

/// A builder for [`Solution`](crate::types::Solution).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SolutionBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) solution_arn: ::std::option::Option<::std::string::String>,
    pub(crate) perform_hpo: ::std::option::Option<bool>,
    pub(crate) perform_auto_ml: ::std::option::Option<bool>,
    pub(crate) perform_auto_training: ::std::option::Option<bool>,
    pub(crate) recipe_arn: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) event_type: ::std::option::Option<::std::string::String>,
    pub(crate) solution_config: ::std::option::Option<crate::types::SolutionConfig>,
    pub(crate) auto_ml_result: ::std::option::Option<crate::types::AutoMlResult>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) latest_solution_version: ::std::option::Option<crate::types::SolutionVersionSummary>,
    pub(crate) latest_solution_update: ::std::option::Option<crate::types::SolutionUpdateSummary>,
}
impl SolutionBuilder {
    /// <p>The name of the solution.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the solution.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the solution.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The ARN of the solution.</p>
    pub fn solution_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.solution_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the solution.</p>
    pub fn set_solution_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.solution_arn = input;
        self
    }
    /// <p>The ARN of the solution.</p>
    pub fn get_solution_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.solution_arn
    }
    /// <p>Whether to perform hyperparameter optimization (HPO) on the chosen recipe. The default is <code>false</code>.</p>
    pub fn perform_hpo(mut self, input: bool) -> Self {
        self.perform_hpo = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to perform hyperparameter optimization (HPO) on the chosen recipe. The default is <code>false</code>.</p>
    pub fn set_perform_hpo(mut self, input: ::std::option::Option<bool>) -> Self {
        self.perform_hpo = input;
        self
    }
    /// <p>Whether to perform hyperparameter optimization (HPO) on the chosen recipe. The default is <code>false</code>.</p>
    pub fn get_perform_hpo(&self) -> &::std::option::Option<bool> {
        &self.perform_hpo
    }
    /// <important>
    /// <p>We don't recommend enabling automated machine learning. Instead, match your use case to the available Amazon Personalize recipes. For more information, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/determining-use-case.html">Determining your use case.</a></p>
    /// </important>
    /// <p>When true, Amazon Personalize performs a search for the best USER_PERSONALIZATION recipe from the list specified in the solution configuration (<code>recipeArn</code> must not be specified). When false (the default), Amazon Personalize uses <code>recipeArn</code> for training.</p>
    pub fn perform_auto_ml(mut self, input: bool) -> Self {
        self.perform_auto_ml = ::std::option::Option::Some(input);
        self
    }
    /// <important>
    /// <p>We don't recommend enabling automated machine learning. Instead, match your use case to the available Amazon Personalize recipes. For more information, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/determining-use-case.html">Determining your use case.</a></p>
    /// </important>
    /// <p>When true, Amazon Personalize performs a search for the best USER_PERSONALIZATION recipe from the list specified in the solution configuration (<code>recipeArn</code> must not be specified). When false (the default), Amazon Personalize uses <code>recipeArn</code> for training.</p>
    pub fn set_perform_auto_ml(mut self, input: ::std::option::Option<bool>) -> Self {
        self.perform_auto_ml = input;
        self
    }
    /// <important>
    /// <p>We don't recommend enabling automated machine learning. Instead, match your use case to the available Amazon Personalize recipes. For more information, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/determining-use-case.html">Determining your use case.</a></p>
    /// </important>
    /// <p>When true, Amazon Personalize performs a search for the best USER_PERSONALIZATION recipe from the list specified in the solution configuration (<code>recipeArn</code> must not be specified). When false (the default), Amazon Personalize uses <code>recipeArn</code> for training.</p>
    pub fn get_perform_auto_ml(&self) -> &::std::option::Option<bool> {
        &self.perform_auto_ml
    }
    /// <p>Specifies whether the solution automatically creates solution versions. The default is <code>True</code> and the solution automatically creates new solution versions every 7 days.</p>
    /// <p>For more information about auto training, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/customizing-solution-config.html">Creating and configuring a solution</a>.</p>
    pub fn perform_auto_training(mut self, input: bool) -> Self {
        self.perform_auto_training = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the solution automatically creates solution versions. The default is <code>True</code> and the solution automatically creates new solution versions every 7 days.</p>
    /// <p>For more information about auto training, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/customizing-solution-config.html">Creating and configuring a solution</a>.</p>
    pub fn set_perform_auto_training(mut self, input: ::std::option::Option<bool>) -> Self {
        self.perform_auto_training = input;
        self
    }
    /// <p>Specifies whether the solution automatically creates solution versions. The default is <code>True</code> and the solution automatically creates new solution versions every 7 days.</p>
    /// <p>For more information about auto training, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/customizing-solution-config.html">Creating and configuring a solution</a>.</p>
    pub fn get_perform_auto_training(&self) -> &::std::option::Option<bool> {
        &self.perform_auto_training
    }
    /// <p>The ARN of the recipe used to create the solution. This is required when <code>performAutoML</code> is false.</p>
    pub fn recipe_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recipe_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the recipe used to create the solution. This is required when <code>performAutoML</code> is false.</p>
    pub fn set_recipe_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recipe_arn = input;
        self
    }
    /// <p>The ARN of the recipe used to create the solution. This is required when <code>performAutoML</code> is false.</p>
    pub fn get_recipe_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.recipe_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the dataset group that provides the training data.</p>
    pub fn dataset_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the dataset group that provides the training data.</p>
    pub fn set_dataset_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_group_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the dataset group that provides the training data.</p>
    pub fn get_dataset_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_group_arn
    }
    /// <p>The event type (for example, 'click' or 'like') that is used for training the model. If no <code>eventType</code> is provided, Amazon Personalize uses all interactions for training with equal weight regardless of type.</p>
    pub fn event_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The event type (for example, 'click' or 'like') that is used for training the model. If no <code>eventType</code> is provided, Amazon Personalize uses all interactions for training with equal weight regardless of type.</p>
    pub fn set_event_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_type = input;
        self
    }
    /// <p>The event type (for example, 'click' or 'like') that is used for training the model. If no <code>eventType</code> is provided, Amazon Personalize uses all interactions for training with equal weight regardless of type.</p>
    pub fn get_event_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_type
    }
    /// <p>Describes the configuration properties for the solution.</p>
    pub fn solution_config(mut self, input: crate::types::SolutionConfig) -> Self {
        self.solution_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the configuration properties for the solution.</p>
    pub fn set_solution_config(mut self, input: ::std::option::Option<crate::types::SolutionConfig>) -> Self {
        self.solution_config = input;
        self
    }
    /// <p>Describes the configuration properties for the solution.</p>
    pub fn get_solution_config(&self) -> &::std::option::Option<crate::types::SolutionConfig> {
        &self.solution_config
    }
    /// <p>When <code>performAutoML</code> is true, specifies the best recipe found.</p>
    pub fn auto_ml_result(mut self, input: crate::types::AutoMlResult) -> Self {
        self.auto_ml_result = ::std::option::Option::Some(input);
        self
    }
    /// <p>When <code>performAutoML</code> is true, specifies the best recipe found.</p>
    pub fn set_auto_ml_result(mut self, input: ::std::option::Option<crate::types::AutoMlResult>) -> Self {
        self.auto_ml_result = input;
        self
    }
    /// <p>When <code>performAutoML</code> is true, specifies the best recipe found.</p>
    pub fn get_auto_ml_result(&self) -> &::std::option::Option<crate::types::AutoMlResult> {
        &self.auto_ml_result
    }
    /// <p>The status of the solution.</p>
    /// <p>A solution can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE PENDING &gt; CREATE IN_PROGRESS &gt; ACTIVE -or- CREATE FAILED</p></li>
    /// <li>
    /// <p>DELETE PENDING &gt; DELETE IN_PROGRESS</p></li>
    /// </ul>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the solution.</p>
    /// <p>A solution can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE PENDING &gt; CREATE IN_PROGRESS &gt; ACTIVE -or- CREATE FAILED</p></li>
    /// <li>
    /// <p>DELETE PENDING &gt; DELETE IN_PROGRESS</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the solution.</p>
    /// <p>A solution can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE PENDING &gt; CREATE IN_PROGRESS &gt; ACTIVE -or- CREATE FAILED</p></li>
    /// <li>
    /// <p>DELETE PENDING &gt; DELETE IN_PROGRESS</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The creation date and time (in Unix time) of the solution.</p>
    pub fn creation_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The creation date and time (in Unix time) of the solution.</p>
    pub fn set_creation_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date_time = input;
        self
    }
    /// <p>The creation date and time (in Unix time) of the solution.</p>
    pub fn get_creation_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date_time
    }
    /// <p>The date and time (in Unix time) that the solution was last updated.</p>
    pub fn last_updated_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time (in Unix time) that the solution was last updated.</p>
    pub fn set_last_updated_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_date_time = input;
        self
    }
    /// <p>The date and time (in Unix time) that the solution was last updated.</p>
    pub fn get_last_updated_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_date_time
    }
    /// <p>Describes the latest version of the solution, including the status and the ARN.</p>
    pub fn latest_solution_version(mut self, input: crate::types::SolutionVersionSummary) -> Self {
        self.latest_solution_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the latest version of the solution, including the status and the ARN.</p>
    pub fn set_latest_solution_version(mut self, input: ::std::option::Option<crate::types::SolutionVersionSummary>) -> Self {
        self.latest_solution_version = input;
        self
    }
    /// <p>Describes the latest version of the solution, including the status and the ARN.</p>
    pub fn get_latest_solution_version(&self) -> &::std::option::Option<crate::types::SolutionVersionSummary> {
        &self.latest_solution_version
    }
    /// <p>Provides a summary of the latest updates to the solution.</p>
    pub fn latest_solution_update(mut self, input: crate::types::SolutionUpdateSummary) -> Self {
        self.latest_solution_update = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides a summary of the latest updates to the solution.</p>
    pub fn set_latest_solution_update(mut self, input: ::std::option::Option<crate::types::SolutionUpdateSummary>) -> Self {
        self.latest_solution_update = input;
        self
    }
    /// <p>Provides a summary of the latest updates to the solution.</p>
    pub fn get_latest_solution_update(&self) -> &::std::option::Option<crate::types::SolutionUpdateSummary> {
        &self.latest_solution_update
    }
    /// Consumes the builder and constructs a [`Solution`](crate::types::Solution).
    pub fn build(self) -> crate::types::Solution {
        crate::types::Solution {
            name: self.name,
            solution_arn: self.solution_arn,
            perform_hpo: self.perform_hpo.unwrap_or_default(),
            perform_auto_ml: self.perform_auto_ml.unwrap_or_default(),
            perform_auto_training: self.perform_auto_training,
            recipe_arn: self.recipe_arn,
            dataset_group_arn: self.dataset_group_arn,
            event_type: self.event_type,
            solution_config: self.solution_config,
            auto_ml_result: self.auto_ml_result,
            status: self.status,
            creation_date_time: self.creation_date_time,
            last_updated_date_time: self.last_updated_date_time,
            latest_solution_version: self.latest_solution_version,
            latest_solution_update: self.latest_solution_update,
        }
    }
}
