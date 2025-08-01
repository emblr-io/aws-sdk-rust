// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters for task execution.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MaintenanceWindowTaskInvocationParameters {
    /// <p>The parameters for a <code>RUN_COMMAND</code> task type.</p>
    pub run_command: ::std::option::Option<crate::types::MaintenanceWindowRunCommandParameters>,
    /// <p>The parameters for an <code>AUTOMATION</code> task type.</p>
    pub automation: ::std::option::Option<crate::types::MaintenanceWindowAutomationParameters>,
    /// <p>The parameters for a <code>STEP_FUNCTIONS</code> task type.</p>
    pub step_functions: ::std::option::Option<crate::types::MaintenanceWindowStepFunctionsParameters>,
    /// <p>The parameters for a <code>LAMBDA</code> task type.</p>
    pub lambda: ::std::option::Option<crate::types::MaintenanceWindowLambdaParameters>,
}
impl MaintenanceWindowTaskInvocationParameters {
    /// <p>The parameters for a <code>RUN_COMMAND</code> task type.</p>
    pub fn run_command(&self) -> ::std::option::Option<&crate::types::MaintenanceWindowRunCommandParameters> {
        self.run_command.as_ref()
    }
    /// <p>The parameters for an <code>AUTOMATION</code> task type.</p>
    pub fn automation(&self) -> ::std::option::Option<&crate::types::MaintenanceWindowAutomationParameters> {
        self.automation.as_ref()
    }
    /// <p>The parameters for a <code>STEP_FUNCTIONS</code> task type.</p>
    pub fn step_functions(&self) -> ::std::option::Option<&crate::types::MaintenanceWindowStepFunctionsParameters> {
        self.step_functions.as_ref()
    }
    /// <p>The parameters for a <code>LAMBDA</code> task type.</p>
    pub fn lambda(&self) -> ::std::option::Option<&crate::types::MaintenanceWindowLambdaParameters> {
        self.lambda.as_ref()
    }
}
impl MaintenanceWindowTaskInvocationParameters {
    /// Creates a new builder-style object to manufacture [`MaintenanceWindowTaskInvocationParameters`](crate::types::MaintenanceWindowTaskInvocationParameters).
    pub fn builder() -> crate::types::builders::MaintenanceWindowTaskInvocationParametersBuilder {
        crate::types::builders::MaintenanceWindowTaskInvocationParametersBuilder::default()
    }
}

/// A builder for [`MaintenanceWindowTaskInvocationParameters`](crate::types::MaintenanceWindowTaskInvocationParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MaintenanceWindowTaskInvocationParametersBuilder {
    pub(crate) run_command: ::std::option::Option<crate::types::MaintenanceWindowRunCommandParameters>,
    pub(crate) automation: ::std::option::Option<crate::types::MaintenanceWindowAutomationParameters>,
    pub(crate) step_functions: ::std::option::Option<crate::types::MaintenanceWindowStepFunctionsParameters>,
    pub(crate) lambda: ::std::option::Option<crate::types::MaintenanceWindowLambdaParameters>,
}
impl MaintenanceWindowTaskInvocationParametersBuilder {
    /// <p>The parameters for a <code>RUN_COMMAND</code> task type.</p>
    pub fn run_command(mut self, input: crate::types::MaintenanceWindowRunCommandParameters) -> Self {
        self.run_command = ::std::option::Option::Some(input);
        self
    }
    /// <p>The parameters for a <code>RUN_COMMAND</code> task type.</p>
    pub fn set_run_command(mut self, input: ::std::option::Option<crate::types::MaintenanceWindowRunCommandParameters>) -> Self {
        self.run_command = input;
        self
    }
    /// <p>The parameters for a <code>RUN_COMMAND</code> task type.</p>
    pub fn get_run_command(&self) -> &::std::option::Option<crate::types::MaintenanceWindowRunCommandParameters> {
        &self.run_command
    }
    /// <p>The parameters for an <code>AUTOMATION</code> task type.</p>
    pub fn automation(mut self, input: crate::types::MaintenanceWindowAutomationParameters) -> Self {
        self.automation = ::std::option::Option::Some(input);
        self
    }
    /// <p>The parameters for an <code>AUTOMATION</code> task type.</p>
    pub fn set_automation(mut self, input: ::std::option::Option<crate::types::MaintenanceWindowAutomationParameters>) -> Self {
        self.automation = input;
        self
    }
    /// <p>The parameters for an <code>AUTOMATION</code> task type.</p>
    pub fn get_automation(&self) -> &::std::option::Option<crate::types::MaintenanceWindowAutomationParameters> {
        &self.automation
    }
    /// <p>The parameters for a <code>STEP_FUNCTIONS</code> task type.</p>
    pub fn step_functions(mut self, input: crate::types::MaintenanceWindowStepFunctionsParameters) -> Self {
        self.step_functions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The parameters for a <code>STEP_FUNCTIONS</code> task type.</p>
    pub fn set_step_functions(mut self, input: ::std::option::Option<crate::types::MaintenanceWindowStepFunctionsParameters>) -> Self {
        self.step_functions = input;
        self
    }
    /// <p>The parameters for a <code>STEP_FUNCTIONS</code> task type.</p>
    pub fn get_step_functions(&self) -> &::std::option::Option<crate::types::MaintenanceWindowStepFunctionsParameters> {
        &self.step_functions
    }
    /// <p>The parameters for a <code>LAMBDA</code> task type.</p>
    pub fn lambda(mut self, input: crate::types::MaintenanceWindowLambdaParameters) -> Self {
        self.lambda = ::std::option::Option::Some(input);
        self
    }
    /// <p>The parameters for a <code>LAMBDA</code> task type.</p>
    pub fn set_lambda(mut self, input: ::std::option::Option<crate::types::MaintenanceWindowLambdaParameters>) -> Self {
        self.lambda = input;
        self
    }
    /// <p>The parameters for a <code>LAMBDA</code> task type.</p>
    pub fn get_lambda(&self) -> &::std::option::Option<crate::types::MaintenanceWindowLambdaParameters> {
        &self.lambda
    }
    /// Consumes the builder and constructs a [`MaintenanceWindowTaskInvocationParameters`](crate::types::MaintenanceWindowTaskInvocationParameters).
    pub fn build(self) -> crate::types::MaintenanceWindowTaskInvocationParameters {
        crate::types::MaintenanceWindowTaskInvocationParameters {
            run_command: self.run_command,
            automation: self.automation,
            step_functions: self.step_functions,
            lambda: self.lambda,
        }
    }
}
