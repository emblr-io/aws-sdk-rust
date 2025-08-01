// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a hardware system model (shape) that's available for an Exadata infrastructure. The shape determines resources, such as CPU cores, memory, and storage, to allocate to the Exadata infrastructure.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DbSystemShapeSummary {
    /// <p>The maximum number of CPU cores that can be enabled for the shape.</p>
    pub available_core_count: ::std::option::Option<i32>,
    /// <p>The maximum number of CPU cores per DB node that can be enabled for the shape.</p>
    pub available_core_count_per_node: ::std::option::Option<i32>,
    /// <p>The maximum amount of data storage, in terabytes (TB), that can be enabled for the shape.</p>
    pub available_data_storage_in_tbs: ::std::option::Option<i32>,
    /// <p>The maximum amount of data storage, in terabytes (TB), that's available per storage server for the shape.</p>
    pub available_data_storage_per_server_in_tbs: ::std::option::Option<i32>,
    /// <p>The maximum amount of DB node storage, in gigabytes (GB), that's available per DB node for the shape.</p>
    pub available_db_node_per_node_in_gbs: ::std::option::Option<i32>,
    /// <p>The maximum amount of DB node storage, in gigabytes (GB), that can be enabled for the shape.</p>
    pub available_db_node_storage_in_gbs: ::std::option::Option<i32>,
    /// <p>The maximum amount of memory, in gigabytes (GB), that can be enabled for the shape.</p>
    pub available_memory_in_gbs: ::std::option::Option<i32>,
    /// <p>The maximum amount of memory, in gigabytes (GB), that's available per DB node for the shape.</p>
    pub available_memory_per_node_in_gbs: ::std::option::Option<i32>,
    /// <p>The discrete number by which the CPU core count for the shape can be increased or decreased.</p>
    pub core_count_increment: ::std::option::Option<i32>,
    /// <p>The maximum number of Exadata storage servers that's available for the shape.</p>
    pub max_storage_count: ::std::option::Option<i32>,
    /// <p>The maximum number of compute servers that is available for the shape.</p>
    pub maximum_node_count: ::std::option::Option<i32>,
    /// <p>The minimum number of CPU cores that can be enabled per node for the shape.</p>
    pub min_core_count_per_node: ::std::option::Option<i32>,
    /// <p>The minimum amount of data storage, in terabytes (TB), that must be allocated for the shape.</p>
    pub min_data_storage_in_tbs: ::std::option::Option<i32>,
    /// <p>The minimum amount of DB node storage, in gigabytes (GB), that must be allocated per DB node for the shape.</p>
    pub min_db_node_storage_per_node_in_gbs: ::std::option::Option<i32>,
    /// <p>The minimum amount of memory, in gigabytes (GB), that must be allocated per DB node for the shape.</p>
    pub min_memory_per_node_in_gbs: ::std::option::Option<i32>,
    /// <p>The minimum number of Exadata storage servers that are available for the shape.</p>
    pub min_storage_count: ::std::option::Option<i32>,
    /// <p>The minimum number of CPU cores that can be enabled for the shape.</p>
    pub minimum_core_count: ::std::option::Option<i32>,
    /// <p>The minimum number of compute servers that are available for the shape.</p>
    pub minimum_node_count: ::std::option::Option<i32>,
    /// <p>The runtime minimum number of CPU cores that can be enabled for the shape.</p>
    pub runtime_minimum_core_count: ::std::option::Option<i32>,
    /// <p>The family of the shape.</p>
    pub shape_family: ::std::option::Option<::std::string::String>,
    /// <p>The shape type. This property is determined by the CPU hardware.</p>
    pub shape_type: ::std::option::Option<crate::types::ShapeType>,
    /// <p>The name of the shape.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The OCI model compute model used when you create or clone an instance: ECPU or OCPU. An ECPU is an abstracted measure of compute resources. ECPUs are based on the number of cores elastically allocated from a pool of compute and storage servers. An OCPU is a legacy physical measure of compute resources. OCPUs are based on the physical core of a processor with hyper-threading enabled.</p>
    pub compute_model: ::std::option::Option<crate::types::ComputeModel>,
    /// <p>Indicates whether the hardware system model supports configurable database and server storage types.</p>
    pub are_server_types_supported: ::std::option::Option<bool>,
}
impl DbSystemShapeSummary {
    /// <p>The maximum number of CPU cores that can be enabled for the shape.</p>
    pub fn available_core_count(&self) -> ::std::option::Option<i32> {
        self.available_core_count
    }
    /// <p>The maximum number of CPU cores per DB node that can be enabled for the shape.</p>
    pub fn available_core_count_per_node(&self) -> ::std::option::Option<i32> {
        self.available_core_count_per_node
    }
    /// <p>The maximum amount of data storage, in terabytes (TB), that can be enabled for the shape.</p>
    pub fn available_data_storage_in_tbs(&self) -> ::std::option::Option<i32> {
        self.available_data_storage_in_tbs
    }
    /// <p>The maximum amount of data storage, in terabytes (TB), that's available per storage server for the shape.</p>
    pub fn available_data_storage_per_server_in_tbs(&self) -> ::std::option::Option<i32> {
        self.available_data_storage_per_server_in_tbs
    }
    /// <p>The maximum amount of DB node storage, in gigabytes (GB), that's available per DB node for the shape.</p>
    pub fn available_db_node_per_node_in_gbs(&self) -> ::std::option::Option<i32> {
        self.available_db_node_per_node_in_gbs
    }
    /// <p>The maximum amount of DB node storage, in gigabytes (GB), that can be enabled for the shape.</p>
    pub fn available_db_node_storage_in_gbs(&self) -> ::std::option::Option<i32> {
        self.available_db_node_storage_in_gbs
    }
    /// <p>The maximum amount of memory, in gigabytes (GB), that can be enabled for the shape.</p>
    pub fn available_memory_in_gbs(&self) -> ::std::option::Option<i32> {
        self.available_memory_in_gbs
    }
    /// <p>The maximum amount of memory, in gigabytes (GB), that's available per DB node for the shape.</p>
    pub fn available_memory_per_node_in_gbs(&self) -> ::std::option::Option<i32> {
        self.available_memory_per_node_in_gbs
    }
    /// <p>The discrete number by which the CPU core count for the shape can be increased or decreased.</p>
    pub fn core_count_increment(&self) -> ::std::option::Option<i32> {
        self.core_count_increment
    }
    /// <p>The maximum number of Exadata storage servers that's available for the shape.</p>
    pub fn max_storage_count(&self) -> ::std::option::Option<i32> {
        self.max_storage_count
    }
    /// <p>The maximum number of compute servers that is available for the shape.</p>
    pub fn maximum_node_count(&self) -> ::std::option::Option<i32> {
        self.maximum_node_count
    }
    /// <p>The minimum number of CPU cores that can be enabled per node for the shape.</p>
    pub fn min_core_count_per_node(&self) -> ::std::option::Option<i32> {
        self.min_core_count_per_node
    }
    /// <p>The minimum amount of data storage, in terabytes (TB), that must be allocated for the shape.</p>
    pub fn min_data_storage_in_tbs(&self) -> ::std::option::Option<i32> {
        self.min_data_storage_in_tbs
    }
    /// <p>The minimum amount of DB node storage, in gigabytes (GB), that must be allocated per DB node for the shape.</p>
    pub fn min_db_node_storage_per_node_in_gbs(&self) -> ::std::option::Option<i32> {
        self.min_db_node_storage_per_node_in_gbs
    }
    /// <p>The minimum amount of memory, in gigabytes (GB), that must be allocated per DB node for the shape.</p>
    pub fn min_memory_per_node_in_gbs(&self) -> ::std::option::Option<i32> {
        self.min_memory_per_node_in_gbs
    }
    /// <p>The minimum number of Exadata storage servers that are available for the shape.</p>
    pub fn min_storage_count(&self) -> ::std::option::Option<i32> {
        self.min_storage_count
    }
    /// <p>The minimum number of CPU cores that can be enabled for the shape.</p>
    pub fn minimum_core_count(&self) -> ::std::option::Option<i32> {
        self.minimum_core_count
    }
    /// <p>The minimum number of compute servers that are available for the shape.</p>
    pub fn minimum_node_count(&self) -> ::std::option::Option<i32> {
        self.minimum_node_count
    }
    /// <p>The runtime minimum number of CPU cores that can be enabled for the shape.</p>
    pub fn runtime_minimum_core_count(&self) -> ::std::option::Option<i32> {
        self.runtime_minimum_core_count
    }
    /// <p>The family of the shape.</p>
    pub fn shape_family(&self) -> ::std::option::Option<&str> {
        self.shape_family.as_deref()
    }
    /// <p>The shape type. This property is determined by the CPU hardware.</p>
    pub fn shape_type(&self) -> ::std::option::Option<&crate::types::ShapeType> {
        self.shape_type.as_ref()
    }
    /// <p>The name of the shape.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The OCI model compute model used when you create or clone an instance: ECPU or OCPU. An ECPU is an abstracted measure of compute resources. ECPUs are based on the number of cores elastically allocated from a pool of compute and storage servers. An OCPU is a legacy physical measure of compute resources. OCPUs are based on the physical core of a processor with hyper-threading enabled.</p>
    pub fn compute_model(&self) -> ::std::option::Option<&crate::types::ComputeModel> {
        self.compute_model.as_ref()
    }
    /// <p>Indicates whether the hardware system model supports configurable database and server storage types.</p>
    pub fn are_server_types_supported(&self) -> ::std::option::Option<bool> {
        self.are_server_types_supported
    }
}
impl DbSystemShapeSummary {
    /// Creates a new builder-style object to manufacture [`DbSystemShapeSummary`](crate::types::DbSystemShapeSummary).
    pub fn builder() -> crate::types::builders::DbSystemShapeSummaryBuilder {
        crate::types::builders::DbSystemShapeSummaryBuilder::default()
    }
}

/// A builder for [`DbSystemShapeSummary`](crate::types::DbSystemShapeSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DbSystemShapeSummaryBuilder {
    pub(crate) available_core_count: ::std::option::Option<i32>,
    pub(crate) available_core_count_per_node: ::std::option::Option<i32>,
    pub(crate) available_data_storage_in_tbs: ::std::option::Option<i32>,
    pub(crate) available_data_storage_per_server_in_tbs: ::std::option::Option<i32>,
    pub(crate) available_db_node_per_node_in_gbs: ::std::option::Option<i32>,
    pub(crate) available_db_node_storage_in_gbs: ::std::option::Option<i32>,
    pub(crate) available_memory_in_gbs: ::std::option::Option<i32>,
    pub(crate) available_memory_per_node_in_gbs: ::std::option::Option<i32>,
    pub(crate) core_count_increment: ::std::option::Option<i32>,
    pub(crate) max_storage_count: ::std::option::Option<i32>,
    pub(crate) maximum_node_count: ::std::option::Option<i32>,
    pub(crate) min_core_count_per_node: ::std::option::Option<i32>,
    pub(crate) min_data_storage_in_tbs: ::std::option::Option<i32>,
    pub(crate) min_db_node_storage_per_node_in_gbs: ::std::option::Option<i32>,
    pub(crate) min_memory_per_node_in_gbs: ::std::option::Option<i32>,
    pub(crate) min_storage_count: ::std::option::Option<i32>,
    pub(crate) minimum_core_count: ::std::option::Option<i32>,
    pub(crate) minimum_node_count: ::std::option::Option<i32>,
    pub(crate) runtime_minimum_core_count: ::std::option::Option<i32>,
    pub(crate) shape_family: ::std::option::Option<::std::string::String>,
    pub(crate) shape_type: ::std::option::Option<crate::types::ShapeType>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) compute_model: ::std::option::Option<crate::types::ComputeModel>,
    pub(crate) are_server_types_supported: ::std::option::Option<bool>,
}
impl DbSystemShapeSummaryBuilder {
    /// <p>The maximum number of CPU cores that can be enabled for the shape.</p>
    pub fn available_core_count(mut self, input: i32) -> Self {
        self.available_core_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of CPU cores that can be enabled for the shape.</p>
    pub fn set_available_core_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.available_core_count = input;
        self
    }
    /// <p>The maximum number of CPU cores that can be enabled for the shape.</p>
    pub fn get_available_core_count(&self) -> &::std::option::Option<i32> {
        &self.available_core_count
    }
    /// <p>The maximum number of CPU cores per DB node that can be enabled for the shape.</p>
    pub fn available_core_count_per_node(mut self, input: i32) -> Self {
        self.available_core_count_per_node = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of CPU cores per DB node that can be enabled for the shape.</p>
    pub fn set_available_core_count_per_node(mut self, input: ::std::option::Option<i32>) -> Self {
        self.available_core_count_per_node = input;
        self
    }
    /// <p>The maximum number of CPU cores per DB node that can be enabled for the shape.</p>
    pub fn get_available_core_count_per_node(&self) -> &::std::option::Option<i32> {
        &self.available_core_count_per_node
    }
    /// <p>The maximum amount of data storage, in terabytes (TB), that can be enabled for the shape.</p>
    pub fn available_data_storage_in_tbs(mut self, input: i32) -> Self {
        self.available_data_storage_in_tbs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of data storage, in terabytes (TB), that can be enabled for the shape.</p>
    pub fn set_available_data_storage_in_tbs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.available_data_storage_in_tbs = input;
        self
    }
    /// <p>The maximum amount of data storage, in terabytes (TB), that can be enabled for the shape.</p>
    pub fn get_available_data_storage_in_tbs(&self) -> &::std::option::Option<i32> {
        &self.available_data_storage_in_tbs
    }
    /// <p>The maximum amount of data storage, in terabytes (TB), that's available per storage server for the shape.</p>
    pub fn available_data_storage_per_server_in_tbs(mut self, input: i32) -> Self {
        self.available_data_storage_per_server_in_tbs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of data storage, in terabytes (TB), that's available per storage server for the shape.</p>
    pub fn set_available_data_storage_per_server_in_tbs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.available_data_storage_per_server_in_tbs = input;
        self
    }
    /// <p>The maximum amount of data storage, in terabytes (TB), that's available per storage server for the shape.</p>
    pub fn get_available_data_storage_per_server_in_tbs(&self) -> &::std::option::Option<i32> {
        &self.available_data_storage_per_server_in_tbs
    }
    /// <p>The maximum amount of DB node storage, in gigabytes (GB), that's available per DB node for the shape.</p>
    pub fn available_db_node_per_node_in_gbs(mut self, input: i32) -> Self {
        self.available_db_node_per_node_in_gbs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of DB node storage, in gigabytes (GB), that's available per DB node for the shape.</p>
    pub fn set_available_db_node_per_node_in_gbs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.available_db_node_per_node_in_gbs = input;
        self
    }
    /// <p>The maximum amount of DB node storage, in gigabytes (GB), that's available per DB node for the shape.</p>
    pub fn get_available_db_node_per_node_in_gbs(&self) -> &::std::option::Option<i32> {
        &self.available_db_node_per_node_in_gbs
    }
    /// <p>The maximum amount of DB node storage, in gigabytes (GB), that can be enabled for the shape.</p>
    pub fn available_db_node_storage_in_gbs(mut self, input: i32) -> Self {
        self.available_db_node_storage_in_gbs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of DB node storage, in gigabytes (GB), that can be enabled for the shape.</p>
    pub fn set_available_db_node_storage_in_gbs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.available_db_node_storage_in_gbs = input;
        self
    }
    /// <p>The maximum amount of DB node storage, in gigabytes (GB), that can be enabled for the shape.</p>
    pub fn get_available_db_node_storage_in_gbs(&self) -> &::std::option::Option<i32> {
        &self.available_db_node_storage_in_gbs
    }
    /// <p>The maximum amount of memory, in gigabytes (GB), that can be enabled for the shape.</p>
    pub fn available_memory_in_gbs(mut self, input: i32) -> Self {
        self.available_memory_in_gbs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of memory, in gigabytes (GB), that can be enabled for the shape.</p>
    pub fn set_available_memory_in_gbs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.available_memory_in_gbs = input;
        self
    }
    /// <p>The maximum amount of memory, in gigabytes (GB), that can be enabled for the shape.</p>
    pub fn get_available_memory_in_gbs(&self) -> &::std::option::Option<i32> {
        &self.available_memory_in_gbs
    }
    /// <p>The maximum amount of memory, in gigabytes (GB), that's available per DB node for the shape.</p>
    pub fn available_memory_per_node_in_gbs(mut self, input: i32) -> Self {
        self.available_memory_per_node_in_gbs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of memory, in gigabytes (GB), that's available per DB node for the shape.</p>
    pub fn set_available_memory_per_node_in_gbs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.available_memory_per_node_in_gbs = input;
        self
    }
    /// <p>The maximum amount of memory, in gigabytes (GB), that's available per DB node for the shape.</p>
    pub fn get_available_memory_per_node_in_gbs(&self) -> &::std::option::Option<i32> {
        &self.available_memory_per_node_in_gbs
    }
    /// <p>The discrete number by which the CPU core count for the shape can be increased or decreased.</p>
    pub fn core_count_increment(mut self, input: i32) -> Self {
        self.core_count_increment = ::std::option::Option::Some(input);
        self
    }
    /// <p>The discrete number by which the CPU core count for the shape can be increased or decreased.</p>
    pub fn set_core_count_increment(mut self, input: ::std::option::Option<i32>) -> Self {
        self.core_count_increment = input;
        self
    }
    /// <p>The discrete number by which the CPU core count for the shape can be increased or decreased.</p>
    pub fn get_core_count_increment(&self) -> &::std::option::Option<i32> {
        &self.core_count_increment
    }
    /// <p>The maximum number of Exadata storage servers that's available for the shape.</p>
    pub fn max_storage_count(mut self, input: i32) -> Self {
        self.max_storage_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of Exadata storage servers that's available for the shape.</p>
    pub fn set_max_storage_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_storage_count = input;
        self
    }
    /// <p>The maximum number of Exadata storage servers that's available for the shape.</p>
    pub fn get_max_storage_count(&self) -> &::std::option::Option<i32> {
        &self.max_storage_count
    }
    /// <p>The maximum number of compute servers that is available for the shape.</p>
    pub fn maximum_node_count(mut self, input: i32) -> Self {
        self.maximum_node_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of compute servers that is available for the shape.</p>
    pub fn set_maximum_node_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_node_count = input;
        self
    }
    /// <p>The maximum number of compute servers that is available for the shape.</p>
    pub fn get_maximum_node_count(&self) -> &::std::option::Option<i32> {
        &self.maximum_node_count
    }
    /// <p>The minimum number of CPU cores that can be enabled per node for the shape.</p>
    pub fn min_core_count_per_node(mut self, input: i32) -> Self {
        self.min_core_count_per_node = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum number of CPU cores that can be enabled per node for the shape.</p>
    pub fn set_min_core_count_per_node(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_core_count_per_node = input;
        self
    }
    /// <p>The minimum number of CPU cores that can be enabled per node for the shape.</p>
    pub fn get_min_core_count_per_node(&self) -> &::std::option::Option<i32> {
        &self.min_core_count_per_node
    }
    /// <p>The minimum amount of data storage, in terabytes (TB), that must be allocated for the shape.</p>
    pub fn min_data_storage_in_tbs(mut self, input: i32) -> Self {
        self.min_data_storage_in_tbs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum amount of data storage, in terabytes (TB), that must be allocated for the shape.</p>
    pub fn set_min_data_storage_in_tbs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_data_storage_in_tbs = input;
        self
    }
    /// <p>The minimum amount of data storage, in terabytes (TB), that must be allocated for the shape.</p>
    pub fn get_min_data_storage_in_tbs(&self) -> &::std::option::Option<i32> {
        &self.min_data_storage_in_tbs
    }
    /// <p>The minimum amount of DB node storage, in gigabytes (GB), that must be allocated per DB node for the shape.</p>
    pub fn min_db_node_storage_per_node_in_gbs(mut self, input: i32) -> Self {
        self.min_db_node_storage_per_node_in_gbs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum amount of DB node storage, in gigabytes (GB), that must be allocated per DB node for the shape.</p>
    pub fn set_min_db_node_storage_per_node_in_gbs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_db_node_storage_per_node_in_gbs = input;
        self
    }
    /// <p>The minimum amount of DB node storage, in gigabytes (GB), that must be allocated per DB node for the shape.</p>
    pub fn get_min_db_node_storage_per_node_in_gbs(&self) -> &::std::option::Option<i32> {
        &self.min_db_node_storage_per_node_in_gbs
    }
    /// <p>The minimum amount of memory, in gigabytes (GB), that must be allocated per DB node for the shape.</p>
    pub fn min_memory_per_node_in_gbs(mut self, input: i32) -> Self {
        self.min_memory_per_node_in_gbs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum amount of memory, in gigabytes (GB), that must be allocated per DB node for the shape.</p>
    pub fn set_min_memory_per_node_in_gbs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_memory_per_node_in_gbs = input;
        self
    }
    /// <p>The minimum amount of memory, in gigabytes (GB), that must be allocated per DB node for the shape.</p>
    pub fn get_min_memory_per_node_in_gbs(&self) -> &::std::option::Option<i32> {
        &self.min_memory_per_node_in_gbs
    }
    /// <p>The minimum number of Exadata storage servers that are available for the shape.</p>
    pub fn min_storage_count(mut self, input: i32) -> Self {
        self.min_storage_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum number of Exadata storage servers that are available for the shape.</p>
    pub fn set_min_storage_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_storage_count = input;
        self
    }
    /// <p>The minimum number of Exadata storage servers that are available for the shape.</p>
    pub fn get_min_storage_count(&self) -> &::std::option::Option<i32> {
        &self.min_storage_count
    }
    /// <p>The minimum number of CPU cores that can be enabled for the shape.</p>
    pub fn minimum_core_count(mut self, input: i32) -> Self {
        self.minimum_core_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum number of CPU cores that can be enabled for the shape.</p>
    pub fn set_minimum_core_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.minimum_core_count = input;
        self
    }
    /// <p>The minimum number of CPU cores that can be enabled for the shape.</p>
    pub fn get_minimum_core_count(&self) -> &::std::option::Option<i32> {
        &self.minimum_core_count
    }
    /// <p>The minimum number of compute servers that are available for the shape.</p>
    pub fn minimum_node_count(mut self, input: i32) -> Self {
        self.minimum_node_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum number of compute servers that are available for the shape.</p>
    pub fn set_minimum_node_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.minimum_node_count = input;
        self
    }
    /// <p>The minimum number of compute servers that are available for the shape.</p>
    pub fn get_minimum_node_count(&self) -> &::std::option::Option<i32> {
        &self.minimum_node_count
    }
    /// <p>The runtime minimum number of CPU cores that can be enabled for the shape.</p>
    pub fn runtime_minimum_core_count(mut self, input: i32) -> Self {
        self.runtime_minimum_core_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The runtime minimum number of CPU cores that can be enabled for the shape.</p>
    pub fn set_runtime_minimum_core_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.runtime_minimum_core_count = input;
        self
    }
    /// <p>The runtime minimum number of CPU cores that can be enabled for the shape.</p>
    pub fn get_runtime_minimum_core_count(&self) -> &::std::option::Option<i32> {
        &self.runtime_minimum_core_count
    }
    /// <p>The family of the shape.</p>
    pub fn shape_family(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.shape_family = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The family of the shape.</p>
    pub fn set_shape_family(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.shape_family = input;
        self
    }
    /// <p>The family of the shape.</p>
    pub fn get_shape_family(&self) -> &::std::option::Option<::std::string::String> {
        &self.shape_family
    }
    /// <p>The shape type. This property is determined by the CPU hardware.</p>
    pub fn shape_type(mut self, input: crate::types::ShapeType) -> Self {
        self.shape_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The shape type. This property is determined by the CPU hardware.</p>
    pub fn set_shape_type(mut self, input: ::std::option::Option<crate::types::ShapeType>) -> Self {
        self.shape_type = input;
        self
    }
    /// <p>The shape type. This property is determined by the CPU hardware.</p>
    pub fn get_shape_type(&self) -> &::std::option::Option<crate::types::ShapeType> {
        &self.shape_type
    }
    /// <p>The name of the shape.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the shape.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the shape.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The OCI model compute model used when you create or clone an instance: ECPU or OCPU. An ECPU is an abstracted measure of compute resources. ECPUs are based on the number of cores elastically allocated from a pool of compute and storage servers. An OCPU is a legacy physical measure of compute resources. OCPUs are based on the physical core of a processor with hyper-threading enabled.</p>
    pub fn compute_model(mut self, input: crate::types::ComputeModel) -> Self {
        self.compute_model = ::std::option::Option::Some(input);
        self
    }
    /// <p>The OCI model compute model used when you create or clone an instance: ECPU or OCPU. An ECPU is an abstracted measure of compute resources. ECPUs are based on the number of cores elastically allocated from a pool of compute and storage servers. An OCPU is a legacy physical measure of compute resources. OCPUs are based on the physical core of a processor with hyper-threading enabled.</p>
    pub fn set_compute_model(mut self, input: ::std::option::Option<crate::types::ComputeModel>) -> Self {
        self.compute_model = input;
        self
    }
    /// <p>The OCI model compute model used when you create or clone an instance: ECPU or OCPU. An ECPU is an abstracted measure of compute resources. ECPUs are based on the number of cores elastically allocated from a pool of compute and storage servers. An OCPU is a legacy physical measure of compute resources. OCPUs are based on the physical core of a processor with hyper-threading enabled.</p>
    pub fn get_compute_model(&self) -> &::std::option::Option<crate::types::ComputeModel> {
        &self.compute_model
    }
    /// <p>Indicates whether the hardware system model supports configurable database and server storage types.</p>
    pub fn are_server_types_supported(mut self, input: bool) -> Self {
        self.are_server_types_supported = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the hardware system model supports configurable database and server storage types.</p>
    pub fn set_are_server_types_supported(mut self, input: ::std::option::Option<bool>) -> Self {
        self.are_server_types_supported = input;
        self
    }
    /// <p>Indicates whether the hardware system model supports configurable database and server storage types.</p>
    pub fn get_are_server_types_supported(&self) -> &::std::option::Option<bool> {
        &self.are_server_types_supported
    }
    /// Consumes the builder and constructs a [`DbSystemShapeSummary`](crate::types::DbSystemShapeSummary).
    pub fn build(self) -> crate::types::DbSystemShapeSummary {
        crate::types::DbSystemShapeSummary {
            available_core_count: self.available_core_count,
            available_core_count_per_node: self.available_core_count_per_node,
            available_data_storage_in_tbs: self.available_data_storage_in_tbs,
            available_data_storage_per_server_in_tbs: self.available_data_storage_per_server_in_tbs,
            available_db_node_per_node_in_gbs: self.available_db_node_per_node_in_gbs,
            available_db_node_storage_in_gbs: self.available_db_node_storage_in_gbs,
            available_memory_in_gbs: self.available_memory_in_gbs,
            available_memory_per_node_in_gbs: self.available_memory_per_node_in_gbs,
            core_count_increment: self.core_count_increment,
            max_storage_count: self.max_storage_count,
            maximum_node_count: self.maximum_node_count,
            min_core_count_per_node: self.min_core_count_per_node,
            min_data_storage_in_tbs: self.min_data_storage_in_tbs,
            min_db_node_storage_per_node_in_gbs: self.min_db_node_storage_per_node_in_gbs,
            min_memory_per_node_in_gbs: self.min_memory_per_node_in_gbs,
            min_storage_count: self.min_storage_count,
            minimum_core_count: self.minimum_core_count,
            minimum_node_count: self.minimum_node_count,
            runtime_minimum_core_count: self.runtime_minimum_core_count,
            shape_family: self.shape_family,
            shape_type: self.shape_type,
            name: self.name,
            compute_model: self.compute_model,
            are_server_types_supported: self.are_server_types_supported,
        }
    }
}
