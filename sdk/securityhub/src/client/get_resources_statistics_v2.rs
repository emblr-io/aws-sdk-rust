// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`GetResourcesStatisticsV2`](crate::operation::get_resources_statistics_v2::builders::GetResourcesStatisticsV2FluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`group_by_rules(ResourceGroupByRule)`](crate::operation::get_resources_statistics_v2::builders::GetResourcesStatisticsV2FluentBuilder::group_by_rules) / [`set_group_by_rules(Option<Vec::<ResourceGroupByRule>>)`](crate::operation::get_resources_statistics_v2::builders::GetResourcesStatisticsV2FluentBuilder::set_group_by_rules):<br>required: **true**<br><p>How resource statistics should be aggregated and organized in the response.</p><br>
    ///   - [`sort_order(SortOrder)`](crate::operation::get_resources_statistics_v2::builders::GetResourcesStatisticsV2FluentBuilder::sort_order) / [`set_sort_order(Option<SortOrder>)`](crate::operation::get_resources_statistics_v2::builders::GetResourcesStatisticsV2FluentBuilder::set_sort_order):<br>required: **false**<br><p>Sorts aggregated statistics.</p><br>
    ///   - [`max_statistic_results(i32)`](crate::operation::get_resources_statistics_v2::builders::GetResourcesStatisticsV2FluentBuilder::max_statistic_results) / [`set_max_statistic_results(Option<i32>)`](crate::operation::get_resources_statistics_v2::builders::GetResourcesStatisticsV2FluentBuilder::set_max_statistic_results):<br>required: **false**<br><p>The maximum number of results to be returned.</p><br>
    /// - On success, responds with [`GetResourcesStatisticsV2Output`](crate::operation::get_resources_statistics_v2::GetResourcesStatisticsV2Output) with field(s):
    ///   - [`group_by_results(Option<Vec::<GroupByResult>>)`](crate::operation::get_resources_statistics_v2::GetResourcesStatisticsV2Output::group_by_results): <p>The aggregated statistics about resources based on the specified grouping rule.</p>
    /// - On failure, responds with [`SdkError<GetResourcesStatisticsV2Error>`](crate::operation::get_resources_statistics_v2::GetResourcesStatisticsV2Error)
    pub fn get_resources_statistics_v2(&self) -> crate::operation::get_resources_statistics_v2::builders::GetResourcesStatisticsV2FluentBuilder {
        crate::operation::get_resources_statistics_v2::builders::GetResourcesStatisticsV2FluentBuilder::new(self.handle.clone())
    }
}
