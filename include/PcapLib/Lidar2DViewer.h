#ifndef LIDAR2DVIEWER_H
#define LIDAR2DVIEWER_H

#include <opencv2/opencv.hpp>
#include <vector>
#include <string>

class Lidar2DViewer {
public:
    /**
     * Constructor: Tạo cửa sổ GUI với kích thước mặc định.
     * @param width Chiều rộng cửa sổ (mặc định 800).
     * @param height Chiều cao cửa sổ (mặc định 600).
     */
    Lidar2DViewer(int width = 800, int height = 600);

    /**
     * Destructor: Đóng cửa sổ tự động.
     */
    ~Lidar2DViewer();

    /**
     * Cập nhật dữ liệu LIDAR: Vẽ các điểm lên canvas.
     * @param lidarPoints Vector các điểm 2D (cv::Point2f: x, y).
     * @param pointColor Màu điểm (mặc định xanh lá, cv::Scalar(0, 255, 0)).
     * @param pointSize Kích thước điểm (mặc định 2 pixel).
     */
    void update(const std::vector<cv::Point2f>& lidarPoints,
                const cv::Scalar& pointColor = cv::Scalar(0, 255, 0),
                int pointSize = 2);

    /**
     * Hiển thị cửa sổ GUI.
     */
    void show();

    /**
     * Đóng cửa sổ và giải phóng tài nguyên.
     */
    void close();

private:
    cv::Mat canvas;                     // Canvas để vẽ (ảnh nền đen).
    int windowWidth;                    // Chiều rộng cửa sổ.
    int windowHeight;                   // Chiều cao cửa sổ.
    std::string windowName;             // Tên cửa sổ.
    bool isWindowCreated;               // Flag kiểm tra cửa sổ đã tạo chưa.
};

#endif // LIDAR2DViewer_H