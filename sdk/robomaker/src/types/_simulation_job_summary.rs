// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary information for a simulation job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SimulationJobSummary {
    /// <p>The Amazon Resource Name (ARN) of the simulation job.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The time, in milliseconds since the epoch, when the simulation job was last updated.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The name of the simulation job.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The status of the simulation job.</p>
    pub status: ::std::option::Option<crate::types::SimulationJobStatus>,
    /// <p>A list of simulation job simulation application names.</p>
    pub simulation_application_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of simulation job robot application names.</p>
    pub robot_application_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The names of the data sources.</p>
    pub data_source_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The compute type for the simulation job summary.</p>
    pub compute_type: ::std::option::Option<crate::types::ComputeType>,
}
impl SimulationJobSummary {
    /// <p>The Amazon Resource Name (ARN) of the simulation job.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The time, in milliseconds since the epoch, when the simulation job was last updated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
    /// <p>The name of the simulation job.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The status of the simulation job.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::SimulationJobStatus> {
        self.status.as_ref()
    }
    /// <p>A list of simulation job simulation application names.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.simulation_application_names.is_none()`.
    pub fn simulation_application_names(&self) -> &[::std::string::String] {
        self.simulation_application_names.as_deref().unwrap_or_default()
    }
    /// <p>A list of simulation job robot application names.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.robot_application_names.is_none()`.
    pub fn robot_application_names(&self) -> &[::std::string::String] {
        self.robot_application_names.as_deref().unwrap_or_default()
    }
    /// <p>The names of the data sources.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.data_source_names.is_none()`.
    pub fn data_source_names(&self) -> &[::std::string::String] {
        self.data_source_names.as_deref().unwrap_or_default()
    }
    /// <p>The compute type for the simulation job summary.</p>
    pub fn compute_type(&self) -> ::std::option::Option<&crate::types::ComputeType> {
        self.compute_type.as_ref()
    }
}
impl SimulationJobSummary {
    /// Creates a new builder-style object to manufacture [`SimulationJobSummary`](crate::types::SimulationJobSummary).
    pub fn builder() -> crate::types::builders::SimulationJobSummaryBuilder {
        crate::types::builders::SimulationJobSummaryBuilder::default()
    }
}

/// A builder for [`SimulationJobSummary`](crate::types::SimulationJobSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SimulationJobSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::SimulationJobStatus>,
    pub(crate) simulation_application_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) robot_application_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) data_source_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) compute_type: ::std::option::Option<crate::types::ComputeType>,
}
impl SimulationJobSummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) of the simulation job.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the simulation job.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the simulation job.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The time, in milliseconds since the epoch, when the simulation job was last updated.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the simulation job was last updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the simulation job was last updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// <p>The name of the simulation job.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the simulation job.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the simulation job.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The status of the simulation job.</p>
    pub fn status(mut self, input: crate::types::SimulationJobStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the simulation job.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SimulationJobStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the simulation job.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SimulationJobStatus> {
        &self.status
    }
    /// Appends an item to `simulation_application_names`.
    ///
    /// To override the contents of this collection use [`set_simulation_application_names`](Self::set_simulation_application_names).
    ///
    /// <p>A list of simulation job simulation application names.</p>
    pub fn simulation_application_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.simulation_application_names.unwrap_or_default();
        v.push(input.into());
        self.simulation_application_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of simulation job simulation application names.</p>
    pub fn set_simulation_application_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.simulation_application_names = input;
        self
    }
    /// <p>A list of simulation job simulation application names.</p>
    pub fn get_simulation_application_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.simulation_application_names
    }
    /// Appends an item to `robot_application_names`.
    ///
    /// To override the contents of this collection use [`set_robot_application_names`](Self::set_robot_application_names).
    ///
    /// <p>A list of simulation job robot application names.</p>
    pub fn robot_application_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.robot_application_names.unwrap_or_default();
        v.push(input.into());
        self.robot_application_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of simulation job robot application names.</p>
    pub fn set_robot_application_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.robot_application_names = input;
        self
    }
    /// <p>A list of simulation job robot application names.</p>
    pub fn get_robot_application_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.robot_application_names
    }
    /// Appends an item to `data_source_names`.
    ///
    /// To override the contents of this collection use [`set_data_source_names`](Self::set_data_source_names).
    ///
    /// <p>The names of the data sources.</p>
    pub fn data_source_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.data_source_names.unwrap_or_default();
        v.push(input.into());
        self.data_source_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The names of the data sources.</p>
    pub fn set_data_source_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.data_source_names = input;
        self
    }
    /// <p>The names of the data sources.</p>
    pub fn get_data_source_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.data_source_names
    }
    /// <p>The compute type for the simulation job summary.</p>
    pub fn compute_type(mut self, input: crate::types::ComputeType) -> Self {
        self.compute_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The compute type for the simulation job summary.</p>
    pub fn set_compute_type(mut self, input: ::std::option::Option<crate::types::ComputeType>) -> Self {
        self.compute_type = input;
        self
    }
    /// <p>The compute type for the simulation job summary.</p>
    pub fn get_compute_type(&self) -> &::std::option::Option<crate::types::ComputeType> {
        &self.compute_type
    }
    /// Consumes the builder and constructs a [`SimulationJobSummary`](crate::types::SimulationJobSummary).
    pub fn build(self) -> crate::types::SimulationJobSummary {
        crate::types::SimulationJobSummary {
            arn: self.arn,
            last_updated_at: self.last_updated_at,
            name: self.name,
            status: self.status,
            simulation_application_names: self.simulation_application_names,
            robot_application_names: self.robot_application_names,
            data_source_names: self.data_source_names,
            compute_type: self.compute_type,
        }
    }
}
