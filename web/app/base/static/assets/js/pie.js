import * as echarts from 'echarts';

var chartDom = document.getElementById('main');
var myChart = echarts.init(chartDom);
var option;

option = {
    backgroundColor: '',
    title: {
        left: 'center',
        top: 20,
        textStyle: {
            color: '#ccc'
        }
    },

    tooltip: {
        trigger: 'item'
    },


    series: [
        {
            name: '',
            type: 'pie',
            radius: '80%',
            center: ['50%', '50%'],
            data: [
                {value: 50, name: '缓冲区溢出'},
                {value: 43, name: '命令注入'},
                {value: 60, name: '信息泄露'}
            ].sort(function (a, b) { return a.value - b.value; }),
            roseType: 'radius',
            label: {
                color: 'rgba(0, 0, 0, 1)'
            },
            labelLine: {
                lineStyle: {
                    color: 'rgba(0, 0, 0, 0.8)'
                },
                smooth: 0.2,
                length: 10,
                length2: 50
            },
            itemStyle: {
                color: '#85c1e9 ',
                shadowBlur: 200,
                shadowColor: 'rgba(255, 255, 225, 1)'
            },

            animationType: 'scale',
            animationEasing: 'elasticOut',
            animationDelay: function (idx) {
                return Math.random() * 200;
            }
        }
    ]
};

option && myChart.setOption(option);
