package com.alibaba.soc.biz.impl;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.alibaba.aim.biz.common.beans.MailMessageBean;
import com.alibaba.aim.biz.common.enums.AppLogType;
import com.alibaba.aim.biz.common.vo.Notify;
import com.alibaba.aim.dal.domain.NtConfig;
import com.alibaba.aim.dal.mapper.NtConfigMapper;
import com.alibaba.aim.utils.AppLogUtil;
import com.alibaba.aim.utils.ArrayUtil;
import com.alibaba.aim.utils.CollectionUtil;
import com.alibaba.aim.utils.ConstantsUtil;
import com.alibaba.aim.utils.DataBaseUtil;
import com.alibaba.aim.utils.DateUtil;
import com.alibaba.aim.utils.EncryptionUtil;
import com.alibaba.aim.utils.MsgMailUtil;
import com.alibaba.aim.utils.MsgUtil;
import com.alibaba.aim.utils.NumberUtil;
import com.alibaba.aim.utils.StringUtil;
import com.alibaba.aim.utils.SysLogUtil;
import com.alibaba.alert.dal.domain.SummaryAlertV1;
import com.alibaba.alert.dal.mapper.SummaryAlertV1Mapper;
import com.alibaba.soc.biz.CountSummaryAlertFixManager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Created by lkpnotice on 2017/6/14.
 */
public class CountSummaryAlertFixManagerImpl  implements CountSummaryAlertFixManager  {

    String tableName = "alert_adl_anti_invasion";
    @Autowired
    JdbcTemplate alertJdbcTemplate;
    @Autowired
    private SummaryAlertV1Mapper summaryAlertMapper;
    @Autowired
    private NtConfigMapper ntConfigMapper;
    @Autowired
    private AppLogUtil appLogUtil;
    @Autowired
    private MsgMailUtil msgMailUtil;
    @Autowired
    private ConstantsUtil constantsUtil;


    private Map<String, SummaryAlertV1> lastSummaryRcds;
    private int notifyRiskValue = 4;
    private Integer[] riskLevelList = new Integer[]{4, 3, 2, 1};
    private String notifyUserMail = "";
    private List<SummaryAlertV1> newSummaryRcds;
    private List<Notify> notifyList;
    private String currBatchTime;
    private List<String> currBatchLogCache;
    /**重复的归并记录*/
    private List<Long> multipleSummaryRcds;
    private SysLogUtil logger = SysLogUtil.getLogger(getClass());

    String timeRecorder = "[CountSummaryAlertFixManagerImpl-time record] ";



    @Override
    public boolean dispatchMain() {
        timeRecorder = "[CountSummaryAlertFixManagerImpl-time record] ";
        long timeStart = System.currentTimeMillis();
        try {
            // 参数、历史数据初始化
            if (!this.initArgs()) {
                return false;
            }

            // 归并计算
            this.doCountRecursiveNameSummaryAlert();
            this.doCountVipSummaryAlert();
            this.doCountHostnameSummaryAlert();
        } catch (Exception e) {
            MsgUtil.sendErrorMsgToDev(e, getClass());
            return false;
        }

        List<String> logInfos = new ArrayList<String>();
        logInfos.add("\n" + System.currentTimeMillis() + " 归并计算完成");

        try {
            // 内容操作(插入、更新）
            this.doUpdateSummaryAlert();
            logInfos.add(System.currentTimeMillis() + " 内容操作(插入、更新)完成");

            // 告警消息发送
            this.doAlertNotify();
            logInfos.add(System.currentTimeMillis() + " 告警发送完成");

            // 更新告警发送成功的记录的状态
            this.updNotifyStatus();
            logInfos.add(System.currentTimeMillis() + " 更新告警发送成功的记录的状态完成");

            String msgBreaker = "\n\n", msg = ArrayUtil.join(currBatchLogCache, msgBreaker);
            appLogUtil.doLog(msg, AppLogType.DTS_TASK, "告警归并计算", currBatchTime);

            logger.infoNotOnline(ArrayUtil.join(logInfos, "\n"));

            long timeEnd = System.currentTimeMillis();
            timeRecorder += "[ start: " + timeStart + " - end: " + timeEnd +" = " + (timeEnd -timeStart) + " ]";
            logger.infoNotOnline(timeRecorder);

            return true;
        } catch (Exception e) {
            MsgUtil.sendErrorMsgToDev(e, getClass());
        }

        logger.infoNotOnline(ArrayUtil.join(logInfos, "\n"));

        return false;
    }





    public boolean initArgs() throws Exception {
        currBatchLogCache = new ArrayList<String>();
        currBatchTime = DateUtil.format(new Date());

        // 从nt_config表得到所有关注的config_key
        List<String> cfgKeys = Arrays.asList(
            "notify_risk_value", "risk_level_split", "detail_src_ip_mapper", "notify_user_mail"
        );
        List<NtConfig> ntCfgs = ntConfigMapper.selectByConfigKeys(cfgKeys);
        Map<String, NtConfig> ntCfgMap = new HashMap<String, NtConfig>();
        for (NtConfig el : ntCfgs) {
            ntCfgMap.put(el.getConfigKey(), el);
        }

        // notify risk value：通知威胁分值
        NtConfig riskValueCfg = ntCfgMap.get("notify_risk_value");
        if (riskValueCfg != null && StringUtil.isNotEmpty(riskValueCfg.getConfigValue())) {
            notifyRiskValue = Integer.parseInt(riskValueCfg.getConfigValue());
        }

        // risk level list：威胁级别列表
        NtConfig riskLevelCfg = ntCfgMap.get("risk_level_split");
        if (riskLevelCfg != null && StringUtil.isNotEmpty(riskLevelCfg.getConfigValue())) {
            String[] tmpStrArray = riskLevelCfg.getConfigValue().split(",");
            Integer[] tmpIntArray = new Integer[tmpStrArray.length];
            for (int i = 0; i < tmpStrArray.length; i++) {
                tmpIntArray[i] = Integer.parseInt(tmpStrArray[i]);
            }
            riskLevelList = tmpIntArray;
        }

        // notify user list：通知人员列表（邮件）
        NtConfig notifyUserMailCfg = ntCfgMap.get("notify_user_mail");
        if (notifyUserMailCfg != null && StringUtil.isNotBlank(notifyUserMailCfg.getConfigValue())) {
            notifyUserMail = notifyUserMailCfg.getConfigValue();
        }


        // 有效的归并记录
        List<SummaryAlertV1> summaryAlerts = summaryAlertMapper.queryByStatus(1);
        lastSummaryRcds = new HashMap<String, SummaryAlertV1>();
        multipleSummaryRcds = new ArrayList<Long>();
        for (SummaryAlertV1 item : summaryAlerts) {
            if (lastSummaryRcds.containsKey(item.getCombinePrimaryKey())) {
                multipleSummaryRcds.add(item.getId());
            } else {
                lastSummaryRcds.put(item.getCombinePrimaryKey(), item);
            }
        }

        newSummaryRcds = new ArrayList<SummaryAlertV1>();
        notifyList = new ArrayList<Notify>();

        String msg = "有效记录数%s";
        currBatchLogCache.add(String.format(msg, lastSummaryRcds.size()));

        this.deleteMultipleSummaryRcds();

        return true;
    }

    /**批量删除重复的归并记录*/
    private void deleteMultipleSummaryRcds(){
        if(CollectionUtil.isEmpty(multipleSummaryRcds)){
            return;
        }

        summaryAlertMapper.deleteByBatch(multipleSummaryRcds);
    }


    protected JdbcTemplate getJdbcHandler() {
        return this.alertJdbcTemplate;
    }

    /**
     *
     * @return
     * @throws Exception
     */

    public int doCountRecursiveNameSummaryAlert() throws Exception {
        String args[] = queryRecursiveSql();
        parseAndAddResult(args[0], args[1], "recursive_name", "getRecursiveName");
        return 0;
    }


    /**
     *
     * @return
     * @throws Exception
     */

    public int doCountVipSummaryAlert() throws Exception {
        String args[] = queryVipSql();
        parseAndAddResult(args[0], args[1], "vip", "getVip");
        return 0;
    }

    /**
     *
     * @return
     * @throws Exception
     */

    public int doCountHostnameSummaryAlert() throws Exception {
        String args[] = queryHostSql();
        parseAndAddResult(args[0], args[1],"hostname", "getHostname");
        return 0;
    }

    /**
     *
     * @param mergeCountSql
     * @param mergeSumStatusSql
     * @param combineType
     * @param summaryAlertMethod
     * @throws Exception
     */
    protected void parseAndAddResult(
        String mergeCountSql, String mergeSumStatusSql, String combineType, String summaryAlertMethod
    ) throws Exception {
        if (!constantsUtil.isOnline()) {
            String tpl = "combineType: %s \n-->countSql: %s\n-->statusSql: %s";
            logger.info(String.format(tpl, combineType, mergeCountSql, mergeSumStatusSql));
        }

        // 为了后续处理方便,将归并告警记录按照归并方式以key-value的形式存放在Map中
        // key  : {String} 归并方式
        // value: {AdlSummaryAlert} 归并记录
        Map<String, SummaryAlertV1> saRecNameMap = new HashMap<String, SummaryAlertV1>();

        // 通过SQL计算细表汇总的记录
        List<Map<String, Object>> summaryAlertList = DataBaseUtil.queryForList(getJdbcHandler().getDataSource(), mergeCountSql);
        SummaryAlertV1 newSa = null;
        ParseVal pv;
        for (Map<String, Object> saMap : summaryAlertList) {
            pv = new ParseVal(saMap);

            newSa = new SummaryAlertV1();
            newSa.setCombineType(combineType);
            newSa.setRecursiveName(pv.getWithDefaultVal("recursive_name"));
            newSa.setVip(this.sort(pv.getWithDefaultVal("vip")));
            newSa.setHostname(this.sort(pv.getWithDefaultVal("hostname")));
            newSa.setInsRuleList(this.sort(pv.getWithDefaultVal("ins_rule_list")));
            newSa.setSec(this.sort(pv.getWithDefaultVal("sec_list")));
            newSa.setRiskValue(this.toInt(pv.getWithDefaultVal("risk_value", "0")));
            newSa.setRiskLevel(this.getRiskLevel(newSa.getRiskValue()));
            newSa.setSrcIp(pv.getWithDefaultVal("src_ip"));

            saRecNameMap.put((String) saMap.get(combineType), newSa);
        }

        List<Map<String, Object>> statusCountList = DataBaseUtil.queryForList(getJdbcHandler().getDataSource(), mergeSumStatusSql);
        for (Map<String, Object> scMap : statusCountList) {
            Object merageVal = scMap.get(combineType);
            if (merageVal == null || StringUtil.isEmpty((String) merageVal)) {
                continue;
            }

            SummaryAlertV1 sa = saRecNameMap.get(merageVal);
            if (sa == null) {
                continue;
            }

            sa.setGmtCreate((Date) scMap.get("gmt_create"));
            sa.setProgress((getInt(scMap, "all_sum") - getInt(scMap, "undo_sum")) + "/" + scMap.get("all_sum"));
            sa.setProgressStatus(((BigDecimal) scMap.get("undo_sum")).intValue() <= 0 ? "已完成" : "未完成");
            sa.setAlgoInfo(getInt(scMap, "algo_valid_sum") + "/" + getInt(scMap, "algo_marked_sum"));

            String priKey = sa.getCombineType() + ":" + (String) sa.getClass().getMethod(summaryAlertMethod).invoke(sa);
            sa.setCombinePrimaryKey(priKey);

            newSummaryRcds.add(sa);
        }

        String msg = String.format("combineType: %s\n"
                + " --> SummaryCountSql:%s\n"
                + " --> StatusCountSql :%s\n"
                + " --> summaryAlertListSize:%s, statusCountListSize:%s, newSummaryRcds size: %s",
            combineType,
            mergeCountSql,
            mergeSumStatusSql,
            summaryAlertList.size(), statusCountList.size(), newSummaryRcds.size()
        );
        currBatchLogCache.add(msg);
    }


    private int getInt(Map<String, Object> dataMap, String key) throws Exception {
        Object valObj = dataMap.get(key);
        if (valObj == null) {
            return 0;
        }

        return ((BigDecimal) valObj).intValue();
    }

    private String getRiskLevel(int levelVal) throws Exception {
        int idx1 = 0, idx2 = 1, idx3 = 2, idx4 = 3;
        if (levelVal >= this.riskLevelList[idx1]) {
            return "严重";
        } else if (levelVal >= this.riskLevelList[idx2]) {
            return "高";
        } else if (levelVal >= this.riskLevelList[idx3]) {
            return "中";
        } else if (levelVal >= this.riskLevelList[idx4]) {
            return "低";
        } else {
            return "低";
        }
    }

    private String sort(Object str) throws Exception {
        String t = (String) str;
        if (StringUtil.isNotEmpty(t)) {
            String[] tmp = t.split(",");
            Arrays.sort(tmp);
            return ArrayUtil.join(tmp, ",");
        }
        return t;
    }

    /** string to int */
    private int toInt(String riskValue) {
        try {
            return (int) Double.parseDouble(riskValue);
        } catch (NumberFormatException e) {
            logger.info("ERROR", e);
        }
        return 0;
    }

    private Long insertSummaryAlert(SummaryAlertV1 sa) throws Exception {
        sa.setCreateTime(new Date());
        sa.setStatus((short) 1);
        summaryAlertMapper.insertSelective(sa);

        return sa.getId();
    }

    private void updSummaryAlert(SummaryAlertV1 sa) throws Exception {
        sa.setHashValue(null);
        summaryAlertMapper.updateByPrimaryKeySelective(sa);
    }

    /**
     * 更新告警状态，插入或者更新
     * @return
     * @throws Exception
     */
    public boolean doUpdateSummaryAlert() throws Exception {
        int addCount = 0, udpCount = 0, delCount = 0;
        String hashSrc, combinePrimaryKey, delSql = null;
        // 所有需要新增的combinePrimaryKey
        List<String> allNewCombineKey = new ArrayList<String>();
        // 重复的combinePrimaryKey
        List<String> dupCombineKey = new ArrayList<String>();
        // 已经插入成功的AdlSummaryAlert
        List<SummaryAlertV1> insertedRcds = new ArrayList<SummaryAlertV1>();

        //logger.infoNotOnline(String.format("归并告警产生了%s条记录", newSummaryRcds.size()));
        timeRecorder += "[newSummaryRcds: " + newSummaryRcds.size() + " ]";


        for (SummaryAlertV1 nSa : this.newSummaryRcds) {
            //保证新计算出的归并告警的惟一性
            if (allNewCombineKey.contains(nSa.getCombinePrimaryKey())) {
                dupCombineKey.add(nSa.getCombinePrimaryKey());
                continue;
            }
            allNewCombineKey.add(nSa.getCombinePrimaryKey());

            // 计算归并告警的hashValue
            hashSrc = "%s%s%s%s%s";
            hashSrc = String.format(
                hashSrc, nSa.getRecursiveName(), nSa.getVip(), nSa.getHostname(),
                nSa.getRiskValue(), nSa.getRiskLevel()
            );
            nSa.setHashValue(EncryptionUtil.md5(hashSrc));

            combinePrimaryKey = nSa.getCombinePrimaryKey();
            // * 在原来的汇中表中没有找到，插入新记录
            if (this.lastSummaryRcds.get(combinePrimaryKey) == null) {
                addCount += 1;

                // 插入汇总记录
                this.insertSummaryAlert(nSa);
                // 将汇总记录的Id，更新到相关联的明细表的summary_id字段上，建立关系
                insertedRcds.add(nSa);

                if (!constantsUtil.isOnline()) {
                    logger.info(String.format("归并告警, '%s' 被插入, 记录ID: %s", combinePrimaryKey, nSa.getId()));
                }

                // * 满足加入到告警列表的条件
                if (nSa.getRiskValue() >= this.notifyRiskValue) {
                    this.notifyList.add(new Notify(nSa, 0));
                }
            }
            // * 在原来的汇中表找到同样combine_primary_key的行，更新该行记录
            else {
                // 得到并从缓存中删除这条记录
                SummaryAlertV1 oSa = this.lastSummaryRcds.remove(combinePrimaryKey);

                boolean isHashValueSame = nSa.getHashValue().equals(oSa.getHashValue());
                boolean isGmtCreateSame = nSa.getGmtCreate().getTime() == oSa.getGmtCreate().getTime();
                boolean isProStatusSame = nSa.getProgressStatus().equals(oSa.getProgressStatus());
                boolean isProgresssSame = nSa.getProgress().equals(oSa.getProgress());
                // 内容一样，不做更新
                if (isHashValueSame && isGmtCreateSame && isProStatusSame && isProgresssSame) {
                    continue;
                }

                udpCount += 1;
                nSa.setId(oSa.getId());

                if (!constantsUtil.isOnline()) {
                    logger.info(String.format("归并告警, %s 归并方式的记录将被更新, 记录ID: %s", combinePrimaryKey, nSa.getId()));
                }

                // 内容不一样，需要更新
                this.updSummaryAlert(nSa);

                // * 满足加入到告警列表的条件
                if (nSa.getRiskValue() > oSa.getRiskValue() && nSa.getRiskValue() >= this.notifyRiskValue) {
                    this.notifyList.add(new Notify(nSa, oSa.getRiskValue()));
                }
            }
        }

        // 启动批量更新告警明细记录
        // this.batchUpdDetailSummaryId(insertedRcds);

        // * 废弃（更新status = 0）原来在汇中表中有而在新的归并记录中没有的汇总记录
        List<String> keys = new ArrayList<String>();
        String ins = null;
        Iterator<Entry<String, SummaryAlertV1>> it = this.lastSummaryRcds.entrySet().iterator();
        Entry<String, SummaryAlertV1> entry;
        while (it.hasNext()){
            entry = it.next();
            SummaryAlertV1 oSa = entry.getValue();
            if (oSa == null) {
                continue;
            }
            keys.add(oSa.getCombinePrimaryKey());
            delCount += 1;
        }

        logger.infoNotOnline(String.format("归并告警记录:  新增了%s条, 更新了%s条, %s条记录会被废弃", addCount, udpCount, delCount));

        this.disableRecordByBatch(keys);

        // do log
        String dupKeys = "";
        if (dupCombineKey.size() > 0) {
            dupKeys = ", filterInvalidSummaryAlert=" + "'" + ArrayUtil.join(dupCombineKey, "','") + "'";
        }
        String msg = "alert_adl_summary_alert add=%s, update=%s, delete(set status=0)=%s%s";
        msg = String.format(msg, addCount, udpCount, delCount, dupKeys);
        currBatchLogCache.add(msg);

        return true;
    }

    private void disableRecordByBatch(List<String> keys) {
        if (CollectionUtil.isEmpty(keys)) {
            return;
        }

        // 每次更新的最大记录数
        int eachCount = 300;
        int size = keys.size(), times = NumberUtil.quotientUp(size, eachCount);
        String ins, delSql;
        for (int i = 0, s, e; i < times; i++) {
            s = i * eachCount;
            e = (i + 1) * eachCount;
            e = e > size ? size : e;
            List<String> subList = keys.subList(s, e);

            ins = "'" + ArrayUtil.join(subList, "','") + "'";
            delSql = String.format(
                "UPDATE %s SET `status`=0 WHERE combine_primary_key IN(%s) AND status = 1",
                "alert_adl_summary_alert", ins
            );
            logger.infoNotOnline(String.format("删除过滤的归并告警记录SQL: %s", delSql));
            getJdbcHandler().execute(delSql);
        }
    }

    /**
     * 邮件通知
     * @return
     * @throws Exception
     */
    public boolean doAlertNotify() throws Exception {
        // 没有需要通知的告警消息 或者 没有需要通知的人, 则不需要发送告警消息
        if (this.notifyList.size() == 0 || StringUtil.isNotBlank(notifyUserMail)) {
            return true;
        }

        // 组织通知内容
        String currTime = DateUtil.format(new Date()), tmpMsg = null;
        List<String> newMsg = new ArrayList<String>(), upgradeMsg = new ArrayList<String>();
        for (Notify n : this.notifyList) {
            if (n.getPreRiskValue() == 0) {
                // 新增告警
                tmpMsg = "[AIM]新增告警。应用信息：%s，规则：%s，风险值：%s，告警时间：%s";
                tmpMsg = String.format(tmpMsg, n.getCombinePrimaryKey(), n.getInsRuleList(), n.getRiskValue(), currTime);
                newMsg.add(tmpMsg);
            } else {
                // 升级告警
                tmpMsg = "[AIM]告警升级。应用信息：%s，规则：%s，风险值：%s，告警时间：%s，上次风险值：%s，处理状态：%s";
                tmpMsg = String.format(
                    tmpMsg, n.getCombinePrimaryKey(), n.getInsRuleList(), n.getRiskValue(), currTime, n.getPreRiskValue(),
                    n.getProgressStatus()
                );
                upgradeMsg.add(tmpMsg);
            }

            // 设置为 "已发送告警通知消息" 状态
            n.setSendSucceed(true);
        }

        // 向员工发送邮件
        boolean hasMsgToSend = (CollectionUtil.isNotEmpty(newMsg) || CollectionUtil.isNotEmpty(newMsg));
        if (hasMsgToSend) {
            MailMessageBean mmb = new MailMessageBean();
            mmb.setMailTo(this.notifyUserMail);
            tmpMsg = "告警归并计算告警 - " + DateUtil.format(new Date(), "yyyy-MM-dd");
            mmb.setSubject(tmpMsg);
            tmpMsg = "告警归并计算产生以下归并记录, 请关注:<br/><br/>新增告警:<br/>%s<br/><br/>告警升级:%s";
            tmpMsg = String.format(tmpMsg, ArrayUtil.join(newMsg, "<br/>"), ArrayUtil.join(upgradeMsg, "<br/>"));
            mmb.setText(tmpMsg);

            msgMailUtil.sendMail(mmb);
        }

        return true;
    }

    /**
     * 更新通知数据
     * @throws Exception
     */
    public void updNotifyStatus() throws Exception {
        if (this.notifyList.size() == 0) {
            return;
        }

        String currDateTime, sql, ins;
        List<String> keys = new ArrayList<String>();
        for (Notify n : this.notifyList) {
            if (!n.isSendSucceed()) {
                continue;
            }
            keys.add(n.getCombinePrimaryKey());
        }

        if (keys.size() == 0) {
            return;
        }
        ins = "'" + ArrayUtil.join(keys, "','") + "'";
        currDateTime = DateUtil.format(new Date());

        sql = "UPDATE %s SET is_notified='%s', notify_time='%s' WHERE combine_primary_key IN(%s) AND is_notified != 1 AND status = 1";
        sql = String.format(sql, "alert_adl_summary_alert", "1", currDateTime, ins);

        getJdbcHandler().execute(sql);
    }



   /**
     * 产品线归并
     * 返回值为2个元素String数组，[0]是归并预警SQL [1]是归并预警状态SQL
     * @return
     */
    public String[] queryRecursiveSql(){
        StringBuilder sBuild = createStrBuilderInstance(" ");
        /********************************** 按照产品线归并************************/
        /*第一层查询处理*/
        String sqlSelectVipLv1 = sBuild.append(" SELECT recursive_name, ").
            append(" vip, ").
            append(" HOST, ").
            append(" rule_id, ").
            append(" sec, ").
            append(" max(risk_value) risk_value, ").
            append(" src_ip ").
            toString();

        String sqlSelectHostLv1 = reset(sBuild).append(" SELECT  recursive_name, ").
            append(" vip, ").
            append(" hostname, ").
            append(" rule_id, ").
            append(" sec, ").
            append(" max(risk_value) risk_value, ").
            append(" src_ip ").
            toString();


        String sqlFromLv1 = reset(sBuild).
            append(" from %s ").
            toString();

        String sqlWhereLv1 = reset(sBuild).
            append(" where  1=1 ").
            append(" and gmt_create>=TIMESTAMP(DATE_SUB(CURDATE(),INTERVAL 7 DAY))  ").
            append(" and recursive_name IS NOT NULL ").
            append(" and  recursive_name !='' ").
            append(" and recursive_name NOT LIKE '开发测试%%'  ").
            append(" %s ").
            toString();


        String conditionHost = " AND (hostname  is not  null and  hostname <> '')";
        String conditionVip = " AND (hostname is  null or hostname = '')";

        String groupByHostLv1 = " GROUP BY rule_id, hostname, recursive_name ";
        String groupByVipLv1 = " GROUP BY rule_id, vip, recursive_name ";


        String sqlQueryVipLv1 = reset(sBuild)
            .append(sqlSelectVipLv1)
            .append(String.format(sqlFromLv1,tableName))
            .append(String.format(sqlWhereLv1,conditionVip))
            .append(groupByVipLv1)
            .toString();


        String sqlQueryHostLv1 = reset(sBuild)
            .append(sqlSelectHostLv1)
            .append(String.format(sqlFromLv1,tableName))
            .append(String.format(sqlWhereLv1,conditionHost))
            .append(groupByHostLv1)
            .toString();

        /*第二层查询处理*/
        String sqlQueryVipLv2 = reset(sBuild)
            .append(" select  ")
            .append(" recursive_name, ")
            .append(" GROUP_CONCAT(DISTINCT vip) AS vip,  ")
            .append(" GROUP_CONCAT(DISTINCT HOST) AS hostname, ")
            .append(" SUM(risk_value)/COUNT(DISTINCT vip) AS risk_value, ")
            .append(" GROUP_CONCAT(DISTINCT rule_id) AS ins_rule_list,  ")
            .append(" GROUP_CONCAT(DISTINCT sec) AS sec_list,  ")
            .append(" GROUP_CONCAT(DISTINCT src_ip) AS src_ip  ")
            .append(" from  ")
            .append("(" + sqlQueryVipLv1 + ") as Ta ")
            .append(" group by recursive_name ")
            .toString();

        String sqlQueryHostLv2 = reset(sBuild)
            .append(" select  ")
            .append(" recursive_name, ")
            .append(" GROUP_CONCAT(DISTINCT vip) AS vip,  ")
            .append(" GROUP_CONCAT(DISTINCT hostname) AS hostname, ")
            .append(" SUM(risk_value)/COUNT(DISTINCT hostname) AS risk_value, ")
            .append(" GROUP_CONCAT(DISTINCT rule_id) AS ins_rule_list,  ")
            .append(" GROUP_CONCAT(DISTINCT sec) AS sec_list,  ")
            .append(" GROUP_CONCAT(DISTINCT src_ip) AS src_ip  ")
            .append(" from  ")
            .append("(" + sqlQueryHostLv1 + ") as Tb ")
            .append(" group by recursive_name ")
            .toString();

        /*第三层查询处理*/
        String sqlQueryProdLine = reset(sBuild)
            .append(" select ")
            .append(" recursive_name, ")
            .append(" GROUP_CONCAT(vip) vip, ")
            .append(" GROUP_CONCAT(hostname) hostname,  ")
            .append(" SUM(risk_value) risk_value, ")
            .append(" GROUP_CONCAT(ins_rule_list) ins_rule_list, ")
            .append(" GROUP_CONCAT(sec_list) sec_list, ")
            .append(" GROUP_CONCAT(src_ip) src_ip  ")
            .append(" from ")
            .append(" ( ")
            .append( "(" + sqlQueryVipLv2 + ") UNION ALL (" + sqlQueryHostLv2+ ") ")
            .append(" ) allAlert ")
            .append(" group by recursive_name ")
            .toString();



        /*按产品线归并的状态归并状态查询*/
        String sqlQueryProStatus = reset(sBuild)
            .append(" select  ")
            .append(" recursive_name, ")
            .append(" sum(1) AS all_sum, ")
            .append(" sum(handle_status='未确认') AS undo_sum, ")
            .append(" sum( algo_flag=0) as algo_valid_sum, ")
            .append(" sum(algo_flag in (0,1)) as algo_marked_sum, ")
            .append(" max(STR_TO_DATE(all_alert.gmt_create,'%Y-%m-%d %H:%i:%s')) AS gmt_create  ")
            .append(" from  " + tableName + " all_alert ")
            .append(" where 1=1 ")
            .append(" and  gmt_create>=TIMESTAMP(DATE_SUB(CURDATE(),INTERVAL 7 DAY)) ")
            .append(" and recursive_name IS NOT NULL  ")
            .append(" and recursive_name != ''  ")
            .append(" and recursive_name NOT LIKE '开发测试%%' ")
            .append(" and data_type != 'anomaly' ")
            .append(" GROUP BY recursive_name ")
            .toString();

        return new String[]{sqlQueryProdLine,sqlQueryProStatus};
    }


    public String[] queryVipSql(){
        StringBuilder sBuild = createStrBuilderInstance(" ");
        /********************************** 按照VIP归并************************/
        /*第一层查询处理*/
        String sqlSelectVipLv1 = sBuild.append(" SELECT recursive_name, ").
            append(" vip, ").
            append(" HOST, ").
            append(" rule_id, ").
            append(" sec, ").
            append(" max(risk_value) risk_value, ").
            append(" src_ip ").
            toString();

        String sqlSelectHostLv1 = reset(sBuild).append(" SELECT  recursive_name, ").
            append(" vip, ").
            append(" hostname, ").
            append(" rule_id, ").
            append(" sec, ").
            append(" max(risk_value) risk_value, ").
            append(" src_ip ").
            toString();


        String sqlFromLv1 = reset(sBuild).
            append(" from %s ").
            toString();

        String sqlWhereLv1 = reset(sBuild).
            append(" where  1=1 ").
            append(" and gmt_create>=TIMESTAMP(DATE_SUB(CURDATE(),INTERVAL 7 DAY))  ").
            append(" and (recursive_name IS NULL OR recursive_name = '' OR recursive_name LIKE '开发测试%%') ").
            append(" and vip <> '' ").
            append(" %s ").
            toString();


        String conditionHost = " AND (hostname  is not  null and  hostname <> '')  ";
        String conditionVip = " AND (hostname is  null or hostname = '')  ";

        String groupByHostLv1 = " GROUP BY rule_id, hostname, vip ";
        String groupByVipLv1 = " GROUP BY rule_id, vip ";


        String sqlQueryVipLv1 = reset(sBuild)
            .append(sqlSelectVipLv1)
            .append(String.format(sqlFromLv1,tableName))
            .append(String.format(sqlWhereLv1,conditionVip))
            .append(groupByVipLv1)
            .toString();


        String sqlQueryHostLv1 = reset(sBuild)
            .append(sqlSelectHostLv1)
            .append(String.format(sqlFromLv1,tableName))
            .append(String.format(sqlWhereLv1,conditionHost))
            .append(groupByHostLv1)
            .toString();


        /*第二层查询处理*/
        String sqlQueryVipLv2 = reset(sBuild)
            .append(" select  ")
            .append(" GROUP_CONCAT(DISTINCT recursive_name) AS recursive_name, ")
            .append(" vip,  ")
            .append(" GROUP_CONCAT(DISTINCT HOST) AS hostname, ")
            .append(" SUM(risk_value)/COUNT(DISTINCT vip) AS risk_value, ")
            .append(" GROUP_CONCAT(DISTINCT rule_id) AS ins_rule_list,  ")
            .append(" GROUP_CONCAT(DISTINCT sec) AS sec_list,  ")
            .append(" GROUP_CONCAT(DISTINCT src_ip) AS src_ip  ")
            .append(" from  ")
            .append("(" + sqlQueryVipLv1 + ") as Ta ")
            .append(" group by vip ")
            .toString();

        String sqlQueryHostLv2 = reset(sBuild)
            .append(" select  ")
            .append(" GROUP_CONCAT(DISTINCT recursive_name) AS recursive_name,  ")
            .append(" vip,  ")
            .append(" GROUP_CONCAT(DISTINCT hostname) AS hostname, ")
            .append(" SUM(risk_value)/COUNT(DISTINCT hostname) AS risk_value, ")
            .append(" GROUP_CONCAT(DISTINCT rule_id) AS ins_rule_list,  ")
            .append(" GROUP_CONCAT(DISTINCT sec) AS sec_list,  ")
            .append(" GROUP_CONCAT(DISTINCT src_ip) AS src_ip  ")
            .append(" from  ")
            .append("(" + sqlQueryHostLv1 + ") as Tb ")
            .append(" group by vip ")
            .toString();

        /*第三层查询处理*/

        String sqlQueryVip = reset(sBuild)
            .append(" select ")
            .append(" GROUP_CONCAT(recursive_name) AS recursive_name, ")
            .append(" vip, ")
            .append(" GROUP_CONCAT(hostname) hostname,  ")
            .append(" SUM(risk_value) risk_value, ")
            .append(" GROUP_CONCAT(ins_rule_list) ins_rule_list, ")
            .append(" GROUP_CONCAT(sec_list) sec_list, ")
            .append(" GROUP_CONCAT(src_ip) src_ip  ")
            .append(" from ")
            .append(" ( ")
            .append( "(" + sqlQueryVipLv2 + ") UNION ALL (" + sqlQueryHostLv2+ ") ")
            .append(" ) allAlert ")
            .append(" group by vip ")
            .toString();

        /*按VIP归并的状态归并状态查询*/
        String sqlQueryVipStatus = reset(sBuild)
            .append(" select  ")
            .append(" vip, ")
            .append(" sum(1) AS all_sum, ")
            .append(" sum(handle_status='未确认') AS undo_sum, ")
            .append(" sum( algo_flag=0) as algo_valid_sum, ")
            .append(" sum(algo_flag in (0,1)) as algo_marked_sum, ")
            .append(" max(STR_TO_DATE(all_alert.gmt_create,'%Y-%m-%d %H:%i:%s')) AS gmt_create  ")
            .append(" from  " + tableName + " all_alert ")
            .append(" where 1=1 ")
            .append(" and  gmt_create>=TIMESTAMP(DATE_SUB(CURDATE(),INTERVAL 7 DAY)) ")
            .append(" and  (recursive_name IS NULL OR recursive_name = '' OR recursive_name LIKE '开发测试%%')  ")
            .append(" and  vip <> ''  ")
            .append(" and  data_type != 'anomaly' ")
            .append(" GROUP BY vip ")
            .toString();

        return new String[]{sqlQueryVip,sqlQueryVipStatus};
    }




    /**
     * 按照主机类型进行归并
     * @return
     */
    public String[] queryHostSql(){
        /********************************** 按照HOSTNAME归并************************/
        StringBuilder sBuild = createStrBuilderInstance(" ");
        String sqlSelectHostLv1 = sBuild.append(" SELECT  recursive_name, ").
            append(" vip, ").
            append(" hostname, ").
            append(" rule_id, ").
            append(" sec, ").
            append(" max(risk_value) risk_value, ").
            append(" src_ip ").
            toString();


        String sqlFromLv1 = reset(sBuild).
            append(" from %s ").
            toString();

        String sqlWhereLv1 = reset(sBuild).
            append(" where  1=1 ").
            append(" and gmt_create>=TIMESTAMP(DATE_SUB(CURDATE(),INTERVAL 7 DAY))  ").
            append(" and (recursive_name IS NULL OR recursive_name = '' OR recursive_name LIKE '开发测试%%') ").
            append(" and  ( vip = '' or vip is null ) ").
            append(" %s ").
            toString();

        String conditionHost = " AND (hostname  is not  null and  hostname <> '')  ";

        String groupByHostLv1 = " GROUP BY  rule_id,hostname  ";

        String sqlQueryHostLv1 = reset(sBuild)
            .append(sqlSelectHostLv1)
            .append(String.format(sqlFromLv1,tableName))
            .append(String.format(sqlWhereLv1,conditionHost))
            .append(groupByHostLv1)
            .toString();


        /*第二层查询处理*/
        String sqlQueryHostStr = reset(sBuild)
            .append(" select  ")
            .append(" GROUP_CONCAT(DISTINCT recursive_name) AS recursive_name,  ")
            .append(" hostname, ")
            .append(" SUM(risk_value) AS risk_value, ")
            .append(" GROUP_CONCAT(DISTINCT rule_id) AS ins_rule_list,  ")
            .append(" GROUP_CONCAT(DISTINCT sec) AS sec_list,  ")
            .append(" GROUP_CONCAT(DISTINCT src_ip) AS src_ip  ")
            .append(" from  ")
            .append("(" + sqlQueryHostLv1 + ") as Tb ")
            .append(" group by hostname ")
            .toString();

        /*状态查询*/
        String sqlQueryHostStatus = reset(sBuild)
            .append(" select  ")
            .append(" hostname, ")
            .append(" sum(1) AS all_sum, ")
            .append(" sum(handle_status='未确认') AS undo_sum, ")
            .append(" sum( algo_flag=0) as algo_valid_sum, ")
            .append(" sum(algo_flag in (0,1)) as algo_marked_sum, ")
            .append(" max(STR_TO_DATE(all_alert.gmt_create,'%Y-%m-%d %H:%i:%s')) AS gmt_create  ")
            .append(" from  " + tableName + " all_alert ")
            .append(" where 1=1 ")
            .append(" and  gmt_create>=TIMESTAMP(DATE_SUB(CURDATE(),INTERVAL 7 DAY)) ")
            .append(" and  (recursive_name IS NULL OR recursive_name = '' OR recursive_name LIKE '开发测试%%')  ")
            .append(" and  (vip = '' or vip is null)  ")
            .append(" and  hostname is not null and hostname <> ''  ")
            .append(" and  data_type != 'anomaly' ")
            .append(" GROUP BY hostname ")
            .toString();

        return new String[] {sqlQueryHostStr,sqlQueryHostStatus};
    }

    protected  StringBuilder createStrBuilderInstance(String initStr){
        return new StringBuilder(initStr);
    }

    protected  StringBuilder reset(StringBuilder strBui){
        return strBui.delete(0,strBui.length());
    }


    private class ParseVal {
        Map<String, Object> saMap;

        public ParseVal(Map<String, Object> saMap) {
            this.saMap = saMap;
        }

        public String getWithDefaultVal(String key, String... defVal) {
            Object obj = saMap.get(key);
            if (obj == null) {
                return (defVal.length == 0) ? "" : defVal[0];
            }

            return obj.toString();
        }
    }



}
