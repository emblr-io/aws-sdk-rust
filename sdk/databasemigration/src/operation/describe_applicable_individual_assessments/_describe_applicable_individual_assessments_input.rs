// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeApplicableIndividualAssessmentsInput {
    /// <p>Amazon Resource Name (ARN) of a migration task on which you want to base the default list of individual assessments.</p>
    pub replication_task_arn: ::std::option::Option<::std::string::String>,
    /// <p>ARN of a replication instance on which you want to base the default list of individual assessments.</p>
    pub replication_instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>Amazon Resource Name (ARN) of a serverless replication on which you want to base the default list of individual assessments.</p>
    pub replication_config_arn: ::std::option::Option<::std::string::String>,
    /// <p>Name of a database engine that the specified replication instance supports as a source.</p>
    pub source_engine_name: ::std::option::Option<::std::string::String>,
    /// <p>Name of a database engine that the specified replication instance supports as a target.</p>
    pub target_engine_name: ::std::option::Option<::std::string::String>,
    /// <p>Name of the migration type that each provided individual assessment must support.</p>
    pub migration_type: ::std::option::Option<crate::types::MigrationTypeValue>,
    /// <p>Maximum number of records to include in the response. If more records exist than the specified <code>MaxRecords</code> value, a pagination token called a marker is included in the response so that the remaining results can be retrieved.</p>
    pub max_records: ::std::option::Option<i32>,
    /// <p>Optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub marker: ::std::option::Option<::std::string::String>,
}
impl DescribeApplicableIndividualAssessmentsInput {
    /// <p>Amazon Resource Name (ARN) of a migration task on which you want to base the default list of individual assessments.</p>
    pub fn replication_task_arn(&self) -> ::std::option::Option<&str> {
        self.replication_task_arn.as_deref()
    }
    /// <p>ARN of a replication instance on which you want to base the default list of individual assessments.</p>
    pub fn replication_instance_arn(&self) -> ::std::option::Option<&str> {
        self.replication_instance_arn.as_deref()
    }
    /// <p>Amazon Resource Name (ARN) of a serverless replication on which you want to base the default list of individual assessments.</p>
    pub fn replication_config_arn(&self) -> ::std::option::Option<&str> {
        self.replication_config_arn.as_deref()
    }
    /// <p>Name of a database engine that the specified replication instance supports as a source.</p>
    pub fn source_engine_name(&self) -> ::std::option::Option<&str> {
        self.source_engine_name.as_deref()
    }
    /// <p>Name of a database engine that the specified replication instance supports as a target.</p>
    pub fn target_engine_name(&self) -> ::std::option::Option<&str> {
        self.target_engine_name.as_deref()
    }
    /// <p>Name of the migration type that each provided individual assessment must support.</p>
    pub fn migration_type(&self) -> ::std::option::Option<&crate::types::MigrationTypeValue> {
        self.migration_type.as_ref()
    }
    /// <p>Maximum number of records to include in the response. If more records exist than the specified <code>MaxRecords</code> value, a pagination token called a marker is included in the response so that the remaining results can be retrieved.</p>
    pub fn max_records(&self) -> ::std::option::Option<i32> {
        self.max_records
    }
    /// <p>Optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl DescribeApplicableIndividualAssessmentsInput {
    /// Creates a new builder-style object to manufacture [`DescribeApplicableIndividualAssessmentsInput`](crate::operation::describe_applicable_individual_assessments::DescribeApplicableIndividualAssessmentsInput).
    pub fn builder() -> crate::operation::describe_applicable_individual_assessments::builders::DescribeApplicableIndividualAssessmentsInputBuilder {
        crate::operation::describe_applicable_individual_assessments::builders::DescribeApplicableIndividualAssessmentsInputBuilder::default()
    }
}

/// A builder for [`DescribeApplicableIndividualAssessmentsInput`](crate::operation::describe_applicable_individual_assessments::DescribeApplicableIndividualAssessmentsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeApplicableIndividualAssessmentsInputBuilder {
    pub(crate) replication_task_arn: ::std::option::Option<::std::string::String>,
    pub(crate) replication_instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) replication_config_arn: ::std::option::Option<::std::string::String>,
    pub(crate) source_engine_name: ::std::option::Option<::std::string::String>,
    pub(crate) target_engine_name: ::std::option::Option<::std::string::String>,
    pub(crate) migration_type: ::std::option::Option<crate::types::MigrationTypeValue>,
    pub(crate) max_records: ::std::option::Option<i32>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
}
impl DescribeApplicableIndividualAssessmentsInputBuilder {
    /// <p>Amazon Resource Name (ARN) of a migration task on which you want to base the default list of individual assessments.</p>
    pub fn replication_task_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_task_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of a migration task on which you want to base the default list of individual assessments.</p>
    pub fn set_replication_task_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_task_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of a migration task on which you want to base the default list of individual assessments.</p>
    pub fn get_replication_task_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_task_arn
    }
    /// <p>ARN of a replication instance on which you want to base the default list of individual assessments.</p>
    pub fn replication_instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of a replication instance on which you want to base the default list of individual assessments.</p>
    pub fn set_replication_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_instance_arn = input;
        self
    }
    /// <p>ARN of a replication instance on which you want to base the default list of individual assessments.</p>
    pub fn get_replication_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_instance_arn
    }
    /// <p>Amazon Resource Name (ARN) of a serverless replication on which you want to base the default list of individual assessments.</p>
    pub fn replication_config_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_config_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of a serverless replication on which you want to base the default list of individual assessments.</p>
    pub fn set_replication_config_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_config_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of a serverless replication on which you want to base the default list of individual assessments.</p>
    pub fn get_replication_config_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_config_arn
    }
    /// <p>Name of a database engine that the specified replication instance supports as a source.</p>
    pub fn source_engine_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_engine_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of a database engine that the specified replication instance supports as a source.</p>
    pub fn set_source_engine_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_engine_name = input;
        self
    }
    /// <p>Name of a database engine that the specified replication instance supports as a source.</p>
    pub fn get_source_engine_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_engine_name
    }
    /// <p>Name of a database engine that the specified replication instance supports as a target.</p>
    pub fn target_engine_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_engine_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of a database engine that the specified replication instance supports as a target.</p>
    pub fn set_target_engine_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_engine_name = input;
        self
    }
    /// <p>Name of a database engine that the specified replication instance supports as a target.</p>
    pub fn get_target_engine_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_engine_name
    }
    /// <p>Name of the migration type that each provided individual assessment must support.</p>
    pub fn migration_type(mut self, input: crate::types::MigrationTypeValue) -> Self {
        self.migration_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Name of the migration type that each provided individual assessment must support.</p>
    pub fn set_migration_type(mut self, input: ::std::option::Option<crate::types::MigrationTypeValue>) -> Self {
        self.migration_type = input;
        self
    }
    /// <p>Name of the migration type that each provided individual assessment must support.</p>
    pub fn get_migration_type(&self) -> &::std::option::Option<crate::types::MigrationTypeValue> {
        &self.migration_type
    }
    /// <p>Maximum number of records to include in the response. If more records exist than the specified <code>MaxRecords</code> value, a pagination token called a marker is included in the response so that the remaining results can be retrieved.</p>
    pub fn max_records(mut self, input: i32) -> Self {
        self.max_records = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of records to include in the response. If more records exist than the specified <code>MaxRecords</code> value, a pagination token called a marker is included in the response so that the remaining results can be retrieved.</p>
    pub fn set_max_records(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_records = input;
        self
    }
    /// <p>Maximum number of records to include in the response. If more records exist than the specified <code>MaxRecords</code> value, a pagination token called a marker is included in the response so that the remaining results can be retrieved.</p>
    pub fn get_max_records(&self) -> &::std::option::Option<i32> {
        &self.max_records
    }
    /// <p>Optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>Optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Consumes the builder and constructs a [`DescribeApplicableIndividualAssessmentsInput`](crate::operation::describe_applicable_individual_assessments::DescribeApplicableIndividualAssessmentsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_applicable_individual_assessments::DescribeApplicableIndividualAssessmentsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_applicable_individual_assessments::DescribeApplicableIndividualAssessmentsInput {
                replication_task_arn: self.replication_task_arn,
                replication_instance_arn: self.replication_instance_arn,
                replication_config_arn: self.replication_config_arn,
                source_engine_name: self.source_engine_name,
                target_engine_name: self.target_engine_name,
                migration_type: self.migration_type,
                max_records: self.max_records,
                marker: self.marker,
            },
        )
    }
}
