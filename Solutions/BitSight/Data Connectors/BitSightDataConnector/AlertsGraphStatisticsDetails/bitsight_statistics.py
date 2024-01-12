"""This file contains implementation of alert, graph, and statistics endpoint."""
import inspect
import time
from datetime import datetime
import json
import hashlib
from ..SharedCode.logger import applogger
from ..SharedCode.bitsight_client import BitSight
from ..SharedCode.bitsight_exception import BitSightException
from ..SharedCode.azure_sentinel import MicrosoftSentinel
from ..SharedCode.get_logs_data import get_logs_data
from ..SharedCode.utils import CheckpointManager
from ..SharedCode.consts import API_TOKEN, ALERTS_PAGE_SIZE, DILIGENCE_STATISCTICS_TABLE, INDUSTRIAL_STATISCTICS_TABLE, OBSERVATION_STATISCTICS_TABLE, DILIGENCE_HISTORICAL_STATISTICS_TABLE, GRAPH_DATA_TABLE, ALERTS_DATA_TABLE, COMPANIES, ENDPOINTS

class BitSightStatistics(BitSight):
    def __init__(self, start_time) -> None:
        super().__init__()
        self.start_time = start_time
        self.check_env_var = self.check_environment_var_exist([{"api_token": API_TOKEN},
                   {"diligence_statistics_table_name": DILIGENCE_STATISCTICS_TABLE},
                   {"industrial_statistics_table_name": INDUSTRIAL_STATISCTICS_TABLE},
                   {"observation_statistics_table_name": OBSERVATION_STATISCTICS_TABLE},
                   {"diligence_historical_statistics_table_name": DILIGENCE_HISTORICAL_STATISTICS_TABLE},
                   {"graph_data_table_name": GRAPH_DATA_TABLE},
                   {"alerts_data_table_name": ALERTS_DATA_TABLE},
                   {"companies_list": COMPANIES}])
        self.checkpoint_obj = CheckpointManager()
        self.company_state = self.checkpoint_obj.get_state("statisctics_company")
        self.diligence_statistics_state = self.checkpoint_obj.get_state("diligence_statistics")
        self.industries_statistics_state = self.checkpoint_obj.get_state("industries_statistics")
        self.observations_statistics_state = self.checkpoint_obj.get_state("observations_statistics")
        self.diligence_historical_statistics_state = self.checkpoint_obj.get_state("diligence_historical_statistics")
        self.graph_state = self.checkpoint_obj.get_state("graph_data")
        self.alerts_state = self.checkpoint_obj.get_state("alerts_data")
        self.date_format = "%Y-%m-%d"
        self.diligence_statistics_path = ENDPOINTS['diligence_statistics_url']
        self.industrial_statistics_path = ENDPOINTS['industries_statistics_url']
        self.observation_statistics_path = ENDPOINTS['observations_statistics_url']
        self.diligence_historical_statistics_path = ENDPOINTS['diligence_historical-statistics_url']
        self.graph_data_path = ENDPOINTS['graph_data_url']
        self.alerts_details_path = ENDPOINTS['alerts_url']
        self.companies_str = COMPANIES
        self.generate_auth_token()
    
    def get_risk_vector_data(self, endpoint, endpoint_path, company_name, company_guid, state, table_name):
        """Post the data of diligence/industries/observation_statistics.

        Args:
            endpoint (str): diligence/industries/observation_statistics
            endpoint_path (str): endpoint path
            company_name (str): company name
            company_guid (str): company guid
            table_name (str): name of table to store data
        """
        try:
            data_to_post = []
            risk_vector_data = []
            checkpoint_key = "{}".format(company_guid)
            checkpoint_data = self.checkpoint_obj.get_last_data(state)
            applogger.info("Checkpoint: {}".format(checkpoint_data))
            applogger.info("type checkpoint: {}".format(type(checkpoint_data)))
            last_data = self.checkpoint_obj.get_endpoint_last_data(checkpoint_data, endpoint, checkpoint_key)
            url = self.base_url + endpoint_path
            res_list = self.get_bitsight_data(url)
            if(res_list.get("risk_vectors")):
                risk_data = res_list.get("risk_vectors")
                risk_vectors = risk_data.keys()
                for risk_vector in risk_vectors:
                    risk_vector_detail = risk_data.get(risk_vector)
                    risk_vector_detail['risk_vector'] = risk_vector
                    risk_vector_detail['Company_name'] = company_name
                    data = json.dumps(risk_vector_detail, sort_keys=True)
                    result = hashlib.sha512(data.encode('utf-8'))
                    result_hash = result.hexdigest()
                    if last_data:
                        if (result_hash not in last_data):
                            risk_vector_data.append(risk_vector_detail)
                        data_to_post.append(result_hash)
                    else:
                        risk_vector_data.append(risk_vector_detail)
                        data_to_post.append(result_hash)
                self.send_data_to_sentinel(risk_vector_data, table_name, company_name, endpoint)
            # data_to_post = str(data_to_post)
            self.checkpoint_obj.save_checkpoint(state, checkpoint_data, endpoint, checkpoint_key, data_to_post)
        except BitSightException:
            raise BitSightException()
        except Exception as err:
            applogger.exception("BitSight: GET RISK VECTOR: {}".format(err))
            raise BitSightException()

    def get_results_hash(self, data, p_data, company_name):
        """Encode the data to maintain checkpoint.

        Args:
            data (dict): inner data
            p_data (dict): outer data
            company_name (str): company name

        Returns:
            str: digestSHA512 hexdigest of data
        """
        try:
            data['date'] = p_data.get("date")
            data['grade'] = p_data.get("grade")
            data['company_name'] = company_name
            data = json.dumps(data, sort_keys=True)
            result = hashlib.sha512(data.encode())
            result_hash = result.hexdigest()
            return result_hash
        except Exception as error:
            applogger.exception("BitSight: GET RESULTS HASH: {}".format(error))
            raise BitSightException()
    
    def get_diligence_historical_statistics_details(self, company_name, company_guid):
        """Fetch and post the diligence historical statistics data.

        Args:
            company_name (str): company name
            company_guid (str): company guid
        """
        try:
            checkpoint_data_to_post = []
            post_data = []
            checkpoint_key = "{}".format(company_guid)
            checkpoint_data = self.checkpoint_obj.get_last_data(self.diligence_historical_statistics_state)
            last_data = self.checkpoint_obj.get_endpoint_last_data(checkpoint_data, "diligence_historical-statistics", company_guid)
            url = self.base_url + self.diligence_historical_statistics_path.format(company_guid)
            response = self.get_bitsight_data(url)
            if(response.get("results")):
                results_data = response.get("results")
                for data in results_data:
                    if(data.get("counts")):
                        count_data = data.get("counts")
                        for count_category in count_data:
                            result_hash = self.get_results_hash(count_category, data, company_name)
                            if (last_data and result_hash not in last_data) or not last_data:
                                count_category['grade'] = data['grade']
                                count_category['date'] = data['date']
                                post_data.append(count_category)
                                checkpoint_data_to_post.append(result_hash)
                            else:
                                checkpoint_data_to_post.append(result_hash)
                self.send_data_to_sentinel(
                    post_data,
                    DILIGENCE_HISTORICAL_STATISTICS_TABLE,
                    company_name,
                    "diligence historical statistics")
            # checkpoint_data_to_post = str(checkpoint_data_to_post)
            self.checkpoint_obj.save_checkpoint(self.diligence_historical_statistics_state, checkpoint_data, "diligence_historical-statistics", checkpoint_key, checkpoint_data_to_post)
        except BitSightException:
            raise BitSightException()
        except Exception as err:
            applogger.exception("BitSight: GET DILIGENCE HISTORICAL STATISTICS: {}".format(err))
            raise BitSightException()

    def get_graph_data(self, company_name, company_guid):
        """Fetch and post the graph data.

        Args:
            company_name (str): company name
            company_guid (str): company guid
        """
        try:
            data_to_post = []
            post_data = []
            last_rating = None
            current_rating = None
            rating_diff = None
            last_date = None
            checkpoint_key = "{}".format(company_guid)
            checkpoint_data = self.checkpoint_obj.get_last_data(self.graph_state)
            last_data = self.checkpoint_obj.get_endpoint_last_data(checkpoint_data, "graph_data", company_guid)
            if last_data:
                last_date = datetime.strptime(last_data[0], self.date_format)
                last_rating = last_data[1]
            url = self.base_url + self.graph_data_path.format(company_guid)
            response = self.get_bitsight_data(url)
            if(response.get("ratings")):
                rating_data = response["ratings"]
                sorted_ratings = sorted(rating_data, key=lambda i: i['x'])
                count = 0
                # get rating of every date from response
                for rating in sorted_ratings:
                    rating['Rating_Date'] = rating.pop('x')
                    rating['Rating'] = rating.pop('y')
                    rating['Company_name'] = company_name
                    rating['Rating_differance'] = None
                    date_in_object = datetime.strptime(rating['Rating_Date'], self.date_format)
                    if last_data:
                        if(date_in_object.date() > last_date.date()):
                            current_rating = rating['Rating']
                            rating_diff = int(current_rating) - int(last_rating)
                            rating['Rating_differance'] = rating_diff
                            last_rating = current_rating
                            post_data.append(rating)
                            data_to_post = [rating['Rating_Date'], rating['Rating']]
                        else:
                            data_to_post = [str(last_date.date()), rating['Rating']]
                    else:
                        if count == 0:
                            last_rating = rating['Rating']
                            rating['Rating_differance'] = rating_diff
                        else:
                            current_rating = rating['Rating']
                            rating_diff = int(current_rating) - int(last_rating)
                            rating['Rating_differance'] = rating_diff
                            last_rating = current_rating
                        post_data.append(rating)
                        data_to_post = [rating['Rating_Date'], rating['Rating']]
                        count += 1
            self.send_data_to_sentinel(post_data, GRAPH_DATA_TABLE, company_name, "graph")
            self.checkpoint_obj.save_checkpoint(self.graph_state, checkpoint_data, "graph_data", checkpoint_key, data_to_post)
        except BitSightException:
            raise BitSightException()
        except KeyError as err:
            applogger.exception("bitSight: GET GRAPH DATA: {}".format(err))
            raise BitSightException()
        except Exception as err:
            applogger.exception("BitSight: GET GRAPH DATA: {}".format(err))
            raise BitSightException()

    def get_alerts_details(self, company_name, company_guid):
        """Fetch and post the alert data.

        Args:
            company_name (str): company name
            company_guid (str): company guid
        """
        try:
            data_to_post = None
            checkpoint_key = "{}".format(company_guid)
            checkpoint_data = self.checkpoint_obj.get_last_data(self.alerts_state)
            last_date = self.checkpoint_obj.get_endpoint_last_data(checkpoint_data, "alerts_data", company_guid)
            if last_date:
                last_date = datetime.strptime(last_date, self.date_format).date()
            query_parameter = {
                "limit": ALERTS_PAGE_SIZE,
                "sort": 'alert_date'
            }
            url = self.base_url + self.alerts_details_path.format(company_guid)
            response = self.get_bitsight_data(url, query_parameter)
            next_link = (response.get('links').get('next'))
            alerts_data = []
            c_data = {}
            while next_link:
                query_parameter['offset'] += query_parameter.get("limit")
                c_data['next1'] = self.get_bitsight_data(url, query_parameter)
                next_link = (c_data['next1'].get('links').get('next'))
                response.get('results').extend(c_data['next1'].get('results'))
            is_alert_exist = False
            for alert in response["results"]:
                current_date = alert['alert_date']
                if last_date:
                    if alert['company_name'].lower() == company_name.lower():
                        is_alert_exist = True
                        current_date = datetime.strptime(current_date, self.date_format).date()
                        if(current_date > last_date):
                            data_to_post = alert['alert_date']
                            alerts_data.append(alert)
                        else:
                            data_to_post = str(last_date)
                else:
                    if alert['company_name'].lower() == company_name.lower():
                        is_alert_exist = True
                        data_to_post = alert['alert_date']
                        alerts_data.append(alert)
            if alerts_data:            
                self.send_data_to_sentinel(alerts_data, ALERTS_DATA_TABLE, company_name, "alerts_data")
            else:
                if is_alert_exist:
                    applogger.info(
                        "BitSight: The data of alerts for {} company is already exist.".format(
                            company_name
                            )
                        )
                else:
                    applogger.info(
                        "BitSight: No alert data found for {} company from BitSight.".format(
                            company_name
                            )
                        )
            self.checkpoint_obj.save_checkpoint(self.alerts_state, checkpoint_data, "alerts_data", checkpoint_key, data_to_post)
        except BitSightException:
            raise BitSightException()
        except Exception as err:
            applogger.exception("BitSight: GET ALERT DATA: {}".format(err))
            raise BitSightException()

    def get_all_copmanies_alerts_graph_statisctics_details(self, logs_data, company_names):
        fetching_index = self.get_last_data_index(company_names, self.checkpoint_obj, self.company_state)
        for company_index in range(fetching_index+1, len(logs_data)):
            company_name = logs_data[company_index].get("name_s")
            if int(time.time()) >= self.start_time + 540:
                applogger.info(
                    "BitSight(method=) : 9:00 mins executed hence breaking. In next iteration, start fetching after {}".format(
                    company_name)
                )
                break
            applogger.info("Fetching Index: {}, company name: {}".format(company_index, company_name))
            company_guid = logs_data[company_index].get("guid_g")
            self.get_company_alerts_graph_statisctics_details(company_name, company_guid)
            self.checkpoint_obj.save_checkpoint(self.company_state, company_name, "statisctics_company", company_name_flag=True)

    def get_specified_companies_alerts_graph_statisctics_details(self, logs_data, company_names):
        __method_name = inspect.currentframe().f_code.co_name
        companies_to_get = self.get_specified_companies_list(company_names, self.companies_str)
        company_names = list(map(str.lower, company_names))
        for company in companies_to_get:
            if int(time.time()) >= self.start_time + 540:
                applogger.info(
                    "{}(method={}) : 9:00 mins executed hence breaking. In next iteration, start fetching after {}".format(
                    self.logs_starts_with, __method_name, company_name)
                )
                break
            index = company_names.index(company)
            company_name = logs_data[index].get("name_s")
            company_guid = logs_data[index].get("guid_g")
            self.get_company_alerts_graph_statisctics_details(company_name, company_guid)

    def get_company_alerts_graph_statisctics_details(self, company_name, company_guid):
        self.get_risk_vector_data(
                        "diligence_statistics",
                        self.diligence_statistics_path.format(company_guid),
                        company_name,
                        company_guid,
                        self.diligence_statistics_state,
                        DILIGENCE_STATISCTICS_TABLE)
        self.get_risk_vector_data(
                        "industries_statistics",
                        self.industrial_statistics_path.format(company_guid),
                        company_name,
                        company_guid,
                        self.industries_statistics_state,
                        INDUSTRIAL_STATISCTICS_TABLE)
        self.get_risk_vector_data(
                        "observations_statistics",
                        self.observation_statistics_path.format(company_guid),
                        company_name,
                        company_guid,
                        self.observations_statistics_state,
                        OBSERVATION_STATISCTICS_TABLE)
        self.get_diligence_historical_statistics_details(company_name, company_guid)
        self.get_graph_data(company_name, company_guid)
        self.get_alerts_details(company_name, company_guid)
    
    def get_bitsight_data_into_sentinel(self):
        """Implement API of portfolio, fetch guid of companies."""
        try:
            applogger.info("BitSight: Started fetching companies from portfolio endpoint.")
            if not self.check_env_var:
                raise BitSightException("Some Environment variables are not set so exiting the app.")
            logs_data, flag = get_logs_data()
            if not flag:
                applogger.warning("Portfolio Companies are not available yet.")
                return
            logs_data = sorted(logs_data, key=lambda x: x["name_s"])
            company_names = [data["name_s"] for data in logs_data]
            if (self.companies_str.strip()).lower() == "all": 
                self.get_all_copmanies_alerts_graph_statisctics_details(logs_data, company_names)
            else:
                self.get_specified_companies_alerts_graph_statisctics_details(logs_data, company_names) 
        except BitSightException:
            raise BitSightException()
        except Exception as err:
            applogger.exception("BitSight: GET COMPANY: {}".format(err))
            raise BitSightException()
